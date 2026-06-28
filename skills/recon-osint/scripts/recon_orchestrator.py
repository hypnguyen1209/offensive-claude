#!/usr/bin/env python3
"""
recon_orchestrator.py — End-to-end external recon pipeline for a root domain.

Chains the modern ProjectDiscovery toolchain in the CORRECT order:
  passive enum (subfinder/amass/crt.sh) -> permutations (alterx) -> RESOLVE (puredns)
  -> probe+fingerprint (httpx) -> crawl (katana) -> archive (gau) -> nuclei triage.
All intermediate output is JSONL where possible so re-runs can be diffed.

USAGE:
  python3 recon_orchestrator.py -d target.com -o out/ --resolvers resolvers.txt [--nuclei] [--brute WORDLIST]

DEPENDENCIES (install separately, on $PATH):
  subfinder, amass (optional), puredns + massdns, alterx, httpx, katana, gau, nuclei (optional), jq
  Validate resolvers first:  dnsvalidator -tL https://public-dns.info/nameservers.txt -o resolvers.txt
  Pure-python fallback for crt.sh uses only the stdlib (urllib).

OPSEC: passive stages are silent on target; puredns/httpx/katana/nuclei touch live infra.
Tune --rate to stay under the radar. Set a browser UA via HTTPX_UA env var.

Authorized engagements only.
"""
import argparse
import json
import os
import shutil
import ssl
import subprocess
import sys
import urllib.request
from pathlib import Path

UA = os.environ.get("HTTPX_UA",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def run(cmd, outfile=None, check=False):
    """Run a command, optionally appending stdout to outfile. Returns exit code."""
    print(f"[*] $ {' '.join(cmd)}", file=sys.stderr)
    try:
        if outfile:
            with open(outfile, "a", encoding="utf-8") as fh:
                p = subprocess.run(cmd, stdout=fh, stderr=subprocess.DEVNULL)
        else:
            p = subprocess.run(cmd, stderr=subprocess.DEVNULL)
        if check and p.returncode != 0:
            print(f"[!] {cmd[0]} exited {p.returncode}", file=sys.stderr)
        return p.returncode
    except FileNotFoundError:
        print(f"[!] tool not found: {cmd[0]} (skipping)", file=sys.stderr)
        return 127


def crtsh(domain: str, outfile: Path):
    """Stdlib-only certificate-transparency pull (fallback when no other CT tool)."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    ctx = ssl.create_default_context()
    names = set()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=40, context=ctx) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        for row in data:
            for n in row.get("name_value", "").splitlines():
                n = n.strip().lstrip("*.").lower()
                if n.endswith(domain):
                    names.add(n)
    except Exception as e:  # noqa: BLE001
        print(f"[!] crt.sh fetch failed: {e}", file=sys.stderr)
    with open(outfile, "w", encoding="utf-8") as fh:
        fh.write("\n".join(sorted(names)) + ("\n" if names else ""))
    print(f"[+] crt.sh: {len(names)} names", file=sys.stderr)


def dedup(files, out: Path):
    seen = set()
    for f in files:
        if Path(f).exists():
            for line in Path(f).read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip().lower()
                if line:
                    seen.add(line)
    out.write_text("\n".join(sorted(seen)) + ("\n" if seen else ""), encoding="utf-8")
    return len(seen)


def main():
    ap = argparse.ArgumentParser(description="External recon orchestrator")
    ap.add_argument("-d", "--domain", required=True)
    ap.add_argument("-o", "--out", default="out")
    ap.add_argument("--resolvers", help="validated resolver file for puredns")
    ap.add_argument("--brute", help="DNS wordlist for puredns bruteforce (optional)")
    ap.add_argument("--rate", type=int, default=1500, help="puredns rate limit")
    ap.add_argument("--httpx-rl", type=int, default=150)
    ap.add_argument("--depth", type=int, default=3, help="katana crawl depth")
    ap.add_argument("--nuclei", action="store_true", help="run nuclei triage on live set")
    ap.add_argument("--no-amass", action="store_true")
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    dom = args.domain

    # ---- 1. PASSIVE ENUM ----
    sf = out / "subs_subfinder.txt"
    if have("subfinder"):
        run(["subfinder", "-d", dom, "-all", "-silent", "-o", str(sf)])
    if not args.no_amass and have("amass"):
        run(["amass", "enum", "-passive", "-d", dom, "-silent", "-o", str(out / "subs_amass.txt")])
    crtsh(dom, out / "subs_crtsh.txt")
    if have("chaos"):
        run(["chaos", "-d", dom, "-silent"], outfile=str(out / "subs_chaos.txt"))

    passive = out / "subs_passive.txt"
    n = dedup(list(out.glob("subs_*.txt")), passive)
    print(f"[+] passive unique: {n}", file=sys.stderr)

    candidates = [str(passive)]

    # ---- 2. PERMUTATIONS ----
    if have("alterx"):
        perms = out / "perms.txt"
        run(["alterx", "-l", str(passive), "-enrich", "-silent"], outfile=str(perms))
        candidates.append(str(perms))

    # ---- 3. BRUTE (optional) ----
    if args.brute and args.resolvers and have("puredns"):
        brute = out / "subs_brute.txt"
        run(["puredns", "bruteforce", args.brute, dom, "-r", args.resolvers,
             "--rate-limit", str(args.rate), "-w", str(brute), "-q"])
        candidates.append(str(brute))

    cand = out / "subs_all_candidates.txt"
    dedup(candidates, cand)

    # ---- 4. RESOLVE (the gate before httpx) ----
    resolved = out / "all_subdomains.txt"
    if args.resolvers and have("puredns"):
        run(["puredns", "resolve", str(cand), "-r", args.resolvers,
             "--rate-limit", str(args.rate), "-w", str(resolved), "-q"])
    elif have("dnsx"):
        run(["dnsx", "-l", str(cand), "-silent", "-o", str(resolved)])
    else:
        shutil.copy(cand, resolved)
    print(f"[+] resolved hosts: {sum(1 for _ in open(resolved))}", file=sys.stderr)

    # ---- 5. PROBE + FINGERPRINT ----
    live_jsonl = out / "httpx_live.jsonl"
    if have("httpx"):
        run(["httpx", "-l", str(resolved), "-sc", "-title", "-td", "-favicon", "-jarm",
             "-asn", "-cdn", "-ip", "-rl", str(args.httpx_rl), "-timeout", "8",
             "-H", f"User-Agent: {UA}", "-json", "-o", str(live_jsonl)])
        # extract plain url + ip lists
        live_urls, ips = set(), set()
        if live_jsonl.exists():
            for line in live_jsonl.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    o = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if o.get("url"):
                    live_urls.add(o["url"])
                for a in (o.get("a") or []):
                    ips.add(a)
        (out / "live_urls.txt").write_text("\n".join(sorted(live_urls)) + "\n", encoding="utf-8")
        (out / "ips.txt").write_text("\n".join(sorted(ips)) + "\n", encoding="utf-8")
        print(f"[+] live urls: {len(live_urls)}  ips: {len(ips)}", file=sys.stderr)

    live_urls_f = out / "live_urls.txt"

    # ---- 6. CRAWL + ARCHIVE ----
    if have("katana") and live_urls_f.exists():
        run(["katana", "-list", str(live_urls_f), "-d", str(args.depth), "-jc", "-jsl",
             "-kf", "all", "-fx", "-c", "15", "-silent", "-o", str(out / "crawl.txt")])
    if have("gau") and live_urls_f.exists():
        # gau reads stdin
        try:
            with open(live_urls_f) as fin, open(out / "archive_urls.txt", "w") as fout:
                subprocess.run(["gau", "--threads", "5", "--subs"], stdin=fin, stdout=fout,
                               stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            pass

    # ---- 7. NUCLEI TRIAGE (optional, loud) ----
    if args.nuclei and have("nuclei") and live_urls_f.exists():
        run(["nuclei", "-l", str(live_urls_f), "-t", "http/cves/", "-t",
             "http/misconfiguration/", "-t", "http/exposures/", "-t", "http/takeovers/",
             "-severity", "medium,high,critical", "-rl", "120", "-jsonl",
             "-o", str(out / "nuclei_findings.jsonl")])

    print(f"[+] DONE. artifacts in {out}/", file=sys.stderr)


if __name__ == "__main__":
    main()
