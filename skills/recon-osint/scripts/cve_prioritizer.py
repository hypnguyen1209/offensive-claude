#!/usr/bin/env python3
"""
cve_prioritizer.py — Enrich + rank CVEs by KEV x EPSS x exposure x CVSS.

Inputs (any combination):
  --from-httpx FILE   httpx JSONL (tech-detect output) -> product/version -> NVD keyword search
  --products FILE     plain 'product version' per line
  --cve-list FILE     explicit CVE IDs (one per line) to enrich
  --ip-file FILE      IPs -> Shodan InternetDB (free, unauth) -> known CVEs + exposure flag

For every CVE it gathers:
  - CVSS base score (NVD 2.0)            - EPSS v4 probability + percentile (FIRST)
  - CISA KEV membership (+ ransomware)   - exposure (CVE seen on an in-scope IP via InternetDB)
then assigns a priority bucket P0..P3 per the matrix in references/cve-exploit-intel.md.

USAGE:
  python3 cve_prioritizer.py --from-httpx httpx_live.jsonl --ip-file ips.txt \
      --nvd-key "$NVD_API_KEY" -o cve_ranked.jsonl

DEPENDENCIES:  pip install requests

OPSEC: touches only NVD / FIRST EPSS / CISA / Shodan APIs — invisible to the target. InternetDB is
passive (queries Shodan's prior scan, not the target). Map CVEs only to in-scope assets. The loud
step (nuclei confirmation) is intentionally NOT run here.

Authorized engagements only.
"""
import argparse
import json
import os
import re
import sys
import time

try:
    import requests
except ImportError:
    print("[!] pip install requests", file=sys.stderr)
    raise

UA = "recon-osint-cve-prioritizer"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
SESS = requests.Session()
SESS.headers.update({"User-Agent": UA})
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def load_kev():
    """Return dict cve -> {dateAdded, ransomware, vendorProject}."""
    try:
        r = SESS.get(KEV_URL, timeout=30)
        data = r.json()
    except Exception as e:  # noqa: BLE001
        print(f"[!] KEV fetch failed: {e}", file=sys.stderr)
        return {}
    out = {}
    for v in data.get("vulnerabilities", []):
        out[v["cveID"].upper()] = {
            "dateAdded": v.get("dateAdded"),
            "ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
            "vendor": v.get("vendorProject"),
        }
    print(f"[+] KEV entries: {len(out)}", file=sys.stderr)
    return out


def nvd_keyword(keyword, nvd_key, limit=20):
    """Search NVD by keyword, return list of (cve_id, cvss, cwe, desc)."""
    headers = {"apiKey": nvd_key} if nvd_key else {}
    try:
        r = SESS.get(NVD_URL, params={"keywordSearch": keyword, "resultsPerPage": limit},
                     headers=headers, timeout=30)
        if r.status_code != 200:
            return []
        data = r.json()
    except Exception:  # noqa: BLE001
        return []
    out = []
    for item in data.get("vulnerabilities", []):
        cve = item["cve"]
        cid = cve["id"].upper()
        cvss = None
        for mkey in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
            metrics = cve.get("metrics", {}).get(mkey)
            if metrics:
                cvss = metrics[0]["cvssData"]["baseScore"]
                break
        cwe = None
        for w in cve.get("weaknesses", []):
            for d in w.get("description", []):
                if d.get("value", "").startswith("CWE-"):
                    cwe = d["value"]
                    break
            if cwe:
                break
        desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
        out.append((cid, cvss, cwe, desc[:160]))
    # NVD rate limit: 5 req/30s (no key) or 50/30s (key)
    time.sleep(0.7 if nvd_key else 6.5)
    return out


def epss_batch(cves):
    """Return dict cve -> (epss_float, percentile_float). Batches up to 100 per call."""
    out = {}
    cves = list(cves)
    for i in range(0, len(cves), 100):
        chunk = cves[i:i + 100]
        try:
            r = SESS.get(EPSS_URL, params={"cve": ",".join(chunk)}, timeout=30)
            for d in r.json().get("data", []):
                out[d["cve"].upper()] = (float(d.get("epss", 0)), float(d.get("percentile", 0)))
        except Exception:  # noqa: BLE001
            continue
        time.sleep(0.5)
    return out


def internetdb(ip):
    """Free, unauth Shodan InternetDB. Return {ports, vulns, hostnames, tags}."""
    try:
        r = SESS.get(f"https://internetdb.shodan.io/{ip}", timeout=12)
        if r.status_code == 200:
            return r.json()
    except Exception:  # noqa: BLE001
        pass
    return {}


def priority(in_kev, epss, exposed, cvss):
    cvss = cvss or 0.0
    if in_kev and exposed:
        return "P0"
    if in_kev:
        return "P1"
    if exposed and epss >= 0.5 and cvss >= 7:
        return "P1"
    if exposed and epss >= 0.1:
        return "P2"
    if exposed and cvss >= 9:
        return "P2"
    return "P3"


def main():
    ap = argparse.ArgumentParser(description="CVE enrichment + prioritization")
    ap.add_argument("--from-httpx", dest="httpx", help="httpx JSONL with tech-detect")
    ap.add_argument("--products", help="plain 'product version' per line")
    ap.add_argument("--cve-list", help="explicit CVE IDs to enrich")
    ap.add_argument("--ip-file", help="IPs for Shodan InternetDB exposure layer")
    ap.add_argument("--nvd-key", default=os.environ.get("NVD_API_KEY"))
    ap.add_argument("-o", "--out", default="cve_ranked.jsonl")
    args = ap.parse_args()

    kev = load_kev()

    # ---- exposure layer (InternetDB) ----
    exposed_cves = set()
    if args.ip_file and os.path.exists(args.ip_file):
        ips = [x.strip() for x in open(args.ip_file, encoding="utf-8", errors="replace")
               if x.strip()]
        for ip in ips:
            d = internetdb(ip)
            for c in d.get("vulns", []):
                exposed_cves.add(c.upper())
        print(f"[+] InternetDB exposed CVEs: {len(exposed_cves)}", file=sys.stderr)

    # ---- gather candidate CVEs ----
    candidates = {}   # cve -> {cvss, cwe, desc, product}
    keywords = []

    if args.httpx and os.path.exists(args.httpx):
        for line in open(args.httpx, encoding="utf-8", errors="replace"):
            try:
                o = json.loads(line)
            except json.JSONDecodeError:
                continue
            for t in (o.get("tech") or o.get("technologies") or []):
                keywords.append(t)
    if args.products and os.path.exists(args.products):
        keywords += [l.strip() for l in open(args.products, encoding="utf-8", errors="replace")
                     if l.strip()]
    keywords = sorted(set(k for k in keywords if k))

    for kw in keywords:
        for cid, cvss, cwe, desc in nvd_keyword(kw, args.nvd_key):
            candidates.setdefault(cid, {"cvss": cvss, "cwe": cwe, "desc": desc, "product": kw})

    if args.cve_list and os.path.exists(args.cve_list):
        for l in open(args.cve_list, encoding="utf-8", errors="replace"):
            for m in CVE_RE.findall(l):
                candidates.setdefault(m.upper(), {"cvss": None, "cwe": None,
                                                  "desc": "", "product": "explicit"})
    # always include exposed CVEs even if not surfaced by keyword
    for c in exposed_cves:
        candidates.setdefault(c, {"cvss": None, "cwe": None, "desc": "", "product": "internetdb"})

    print(f"[+] candidate CVEs: {len(candidates)}", file=sys.stderr)
    if not candidates:
        print("[!] no candidates — supply --from-httpx/--products/--cve-list/--ip-file", file=sys.stderr)
        return

    # ---- EPSS enrichment ----
    epss = epss_batch(candidates.keys())

    # ---- score + emit ----
    ranked = []
    for cid, meta in candidates.items():
        e, pct = epss.get(cid, (0.0, 0.0))
        in_kev = cid in kev
        exposed = cid in exposed_cves
        prio = priority(in_kev, e, exposed, meta["cvss"])
        rec = {
            "cve": cid, "priority": prio, "in_kev": in_kev,
            "kev_ransomware": kev.get(cid, {}).get("ransomware"),
            "epss": round(e, 4), "epss_pct": round(pct, 4),
            "cvss": meta["cvss"], "cwe": meta["cwe"], "exposed": exposed,
            "product": meta["product"], "desc": meta["desc"],
        }
        ranked.append(rec)

    order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    ranked.sort(key=lambda r: (order[r["priority"]], -(r["epss"]), -(r["cvss"] or 0)))

    with open(args.out, "w", encoding="utf-8") as f:
        for r in ranked:
            f.write(json.dumps(r) + "\n")

    p0 = sum(1 for r in ranked if r["priority"] == "P0")
    p1 = sum(1 for r in ranked if r["priority"] == "P1")
    print(f"[+] ranked {len(ranked)} CVEs -> {args.out}  (P0={p0} P1={p1})", file=sys.stderr)
    for r in ranked[:15]:
        print(f"  {r['priority']}  {r['cve']:18} epss={r['epss']:.3f} "
              f"cvss={r['cvss']} kev={r['in_kev']} exp={r['exposed']}  {r['product']}",
              file=sys.stderr)


if __name__ == "__main__":
    main()
