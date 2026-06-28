#!/usr/bin/env python3
"""
beacon_hunter.py - Statistical C2 beacon / long-connection / DNS-tunnel hunter over Zeek logs.

Reimplements the core RITA heuristics with no Docker/DB dependency so you can triage Zeek
conn.log / dns.log (JSON or TSV) directly.

Detections (MITRE ATT&CK):
  - Beaconing:  low coefficient-of-variation of inter-arrival times + tight byte sizes (T1071, T1571)
  - Long connections: single flows of long duration on non-interactive ports          (T1071)
  - Low prevalence:   external dest contacted by very few internal hosts               (T1071)
  - DNS tunneling:    high-entropy / long subdomains, high query volume per domain      (T1071.004, T1572)
  - JA4 mismatch:     optional join against a JA4 blocklist                              (T1071.001)

USAGE:
    # Beacon + long-conn + prevalence over conn.log
    python3 beacon_hunter.py --conn conn.log [--ja4-blocklist bad_ja4.txt] [--json out.json]
    # DNS tunneling over dns.log
    python3 beacon_hunter.py --dns dns.log
    # Both
    python3 beacon_hunter.py --conn conn.log --dns dns.log --min-score 0.7

DEPENDENCIES: Python 3.8+ stdlib only (json, math, statistics, csv).
INPUT: Zeek logs. JSON lines (LogAscii::use_json=T) or classic TSV are both accepted.

This is a defensive network-hunting tool. Authorized use only.
"""
import argparse
import json
import math
import statistics
import sys
from collections import defaultdict
from pathlib import Path

INTERACTIVE_PORTS = {22, 3389, 5900, 5901, 443}  # SSH/RDP/VNC legitimately long-lived (443 noisy)


def read_zeek(path: Path):
    """Yield dict rows from a Zeek log in either JSON-lines or TSV format."""
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        first = fh.readline()
        fh.seek(0)
        if first.lstrip().startswith("{"):
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue
            return
        # TSV: Zeek headers begin with '#fields'
        fields = None
        for line in fh:
            if line.startswith("#fields"):
                fields = line.rstrip("\n").split("\t")[1:]
                continue
            if line.startswith("#") or not line.strip():
                continue
            if fields is None:
                continue
            vals = line.rstrip("\n").split("\t")
            yield {f: (v if v != "-" else "") for f, v in zip(fields, vals)}


def g(row, *keys, default=""):
    for k in keys:
        if k in row and row[k] not in ("", None):
            return row[k]
    return default


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def analyze_conn(path: Path, ja4_blocklist):
    """Group conn.log by (orig, resp, resp_port) and score beaconing/long/prevalence."""
    flows = defaultdict(list)          # key -> [(ts, orig_bytes, resp_bytes, duration), ...]
    dest_hosts = defaultdict(set)      # resp_ip -> {orig_ip}
    ja4_seen = {}                      # (orig,resp,rport,ja4) -> count (dedup)

    for row in read_zeek(path):
        try:
            ts = float(g(row, "ts", default="0") or 0)
            orig = g(row, "id.orig_h", "id_orig_h")
            resp = g(row, "id.resp_h", "id_resp_h")
            rport = int(float(g(row, "id.resp_p", "id_resp_p", default="0") or 0))
            ob = float(g(row, "orig_bytes", default="0") or 0)
            rb = float(g(row, "resp_bytes", default="0") or 0)
            dur = float(g(row, "duration", default="0") or 0)
        except (ValueError, TypeError):
            continue
        if not orig or not resp:
            continue
        flows[(orig, resp, rport)].append((ts, ob, rb, dur))
        dest_hosts[resp].add(orig)

        ja4 = g(row, "ja4", "ja4.ja4")
        if ja4_blocklist and ja4 and ja4 in ja4_blocklist:
            k = (orig, resp, rport, ja4)
            ja4_seen[k] = ja4_seen.get(k, 0) + 1

    findings = []
    for (orig, resp, rport), evs in flows.items():
        # Long connection (single flow), non-interactive port
        max_dur = max(e[3] for e in evs)
        if max_dur > 1800 and rport not in INTERACTIVE_PORTS:
            findings.append({"severity": "medium", "attck": "T1071", "score": 0.7,
                             "title": "Long connection",
                             "detail": f"{orig} -> {resp}:{rport} dur={max_dur:.0f}s"})

        if len(evs) < 8:               # need samples for stable timing stats
            continue
        evs.sort(key=lambda e: e[0])
        deltas = [b[0] - a[0] for a, b in zip(evs, evs[1:]) if b[0] - a[0] > 0]
        if len(deltas) < 6:
            continue
        mean_d = statistics.mean(deltas)
        if mean_d <= 0:
            continue
        cv_time = statistics.pstdev(deltas) / mean_d              # timing regularity
        sizes = [e[1] + e[2] for e in evs]
        mean_s = statistics.mean(sizes) or 1
        cv_size = statistics.pstdev(sizes) / mean_s               # payload uniformity
        prevalence = len(dest_hosts[resp])

        # Lower CVs -> stronger beacon. Combine into a 0..1 score.
        time_score = max(0.0, 1.0 - cv_time / 0.5)                # cv<0.3 strong, ~0 at 0.5
        size_score = max(0.0, 1.0 - cv_size / 1.0)
        prev_score = 1.0 if prevalence <= 1 else max(0.0, 1.0 - (prevalence - 1) / 10)
        score = round(0.55 * time_score + 0.30 * size_score + 0.15 * prev_score, 3)

        if score >= 0.6:
            sev = "high" if score >= 0.8 else "medium"
            findings.append({
                "severity": sev, "attck": "T1071/T1571", "score": score,
                "title": "Periodic beaconing",
                "detail": (f"{orig} -> {resp}:{rport} n={len(evs)} interval~{mean_d:.0f}s "
                           f"cv_t={cv_time:.2f} cv_sz={cv_size:.2f} prevalence={prevalence}")})

    for (orig, resp, rport, ja4), cnt in ja4_seen.items():
        findings.append({"severity": "high", "attck": "T1071.001", "score": 0.9,
                         "title": "Known-bad JA4 fingerprint",
                         "detail": f"{orig} -> {resp}:{rport} ja4={ja4} flows={cnt}"})
    return findings


def analyze_dns(path: Path):
    """Score DNS tunneling: long/high-entropy subdomains and per-domain query volume."""
    per_domain = defaultdict(lambda: {"q": 0, "max_len": 0, "max_ent": 0.0,
                                      "txt": 0, "nxdomain": 0, "src": set()})
    findings = []
    for row in read_zeek(path):
        qry = g(row, "query")
        if not qry:
            continue
        labels = qry.split(".")
        sub = labels[0] if labels else ""
        reg = ".".join(labels[-2:]) if len(labels) >= 2 else qry
        qtype = (g(row, "qtype_name") or "").upper()
        rcode = (g(row, "rcode_name") or "").upper()
        src = g(row, "id.orig_h", "id_orig_h")

        d = per_domain[reg]
        d["q"] += 1
        d["max_len"] = max(d["max_len"], len(sub))
        d["max_ent"] = max(d["max_ent"], shannon_entropy(sub))
        if qtype in ("TXT", "NULL"):
            d["txt"] += 1
        if rcode == "NXDOMAIN":
            d["nxdomain"] += 1
        if src:
            d["src"].add(src)

    for reg, d in per_domain.items():
        score = 0.0
        reasons = []
        if d["max_len"] > 40:
            score += 0.4
            reasons.append(f"sub_len={d['max_len']}")
        if d["max_ent"] > 3.5:
            score += 0.3
            reasons.append(f"entropy={d['max_ent']:.2f}")
        if d["txt"] > 10:
            score += 0.2
            reasons.append(f"txt/null={d['txt']}")
        if d["q"] > 200:
            score += 0.2
            reasons.append(f"queries={d['q']}")
        if d["nxdomain"] > 50:
            score += 0.2
            reasons.append(f"nxdomain={d['nxdomain']}")
        score = round(min(score, 1.0), 3)
        if score >= 0.5:
            sev = "high" if score >= 0.75 else "medium"
            findings.append({
                "severity": sev, "attck": "T1071.004/T1572", "score": score,
                "title": "DNS tunneling / DGA indicators",
                "detail": f"{reg} ({', '.join(reasons)}) hosts={len(d['src'])}"})
    return findings


def main():
    ap = argparse.ArgumentParser(description="Statistical C2 beacon / DNS-tunnel hunter over Zeek logs")
    ap.add_argument("--conn", help="Zeek conn.log (JSON or TSV)")
    ap.add_argument("--dns", help="Zeek dns.log (JSON or TSV)")
    ap.add_argument("--ja4-blocklist", help="file of known-bad JA4 fingerprints (one per line)")
    ap.add_argument("--min-score", type=float, default=0.6, help="minimum score to report")
    ap.add_argument("--json", help="write findings to JSON file")
    args = ap.parse_args()

    if not args.conn and not args.dns:
        ap.error("provide --conn and/or --dns")

    blocklist = set()
    if args.ja4_blocklist:
        blocklist = {l.strip() for l in Path(args.ja4_blocklist).read_text().splitlines()
                     if l.strip() and not l.startswith("#")}

    findings = []
    if args.conn:
        findings += analyze_conn(Path(args.conn), blocklist)
    if args.dns:
        findings += analyze_dns(Path(args.dns))

    findings = [f for f in findings if f.get("score", 1.0) >= args.min_score]
    findings.sort(key=lambda f: f.get("score", 1.0), reverse=True)

    for f in findings:
        print(f"[{f['severity'].upper():8}] {f['attck']:16} score={f.get('score','-'):<6} "
              f"{f['title']}")
        print(f"           {f['detail']}")
    print(f"\n[=] {len(findings)} finding(s) >= score {args.min_score}", file=sys.stderr)

    if args.json:
        Path(args.json).write_text(json.dumps(findings, indent=2), encoding="utf-8")
        print(f"[+] Wrote {args.json}", file=sys.stderr)


if __name__ == "__main__":
    main()
