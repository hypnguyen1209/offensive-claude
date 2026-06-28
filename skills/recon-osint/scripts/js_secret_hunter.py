#!/usr/bin/env python3
"""
js_secret_hunter.py — Download JavaScript bundles, extract endpoints, and mine for hardcoded secrets.

Reads a list of .js URLs (e.g. produced by `katana -jsl` or grep '\\.js$' over crawl output),
fetches each, then:
  - extracts API endpoints / relative paths (LinkFinder-style regex)
  - extracts internal hostnames
  - matches provider-specific + generic secret patterns (with Shannon-entropy gating to cut noise)
  - optionally fetches .map source maps when present

USAGE:
  python3 js_secret_hunter.py -l js_urls.txt -o js_out/ [--threads 20] [--maps]

OUTPUT:
  js_out/endpoints.txt   unique endpoints/paths discovered
  js_out/hosts.txt       unique hostnames referenced
  js_out/secrets.jsonl   {js_url, type, match(redacted), entropy, context}

DEPENDENCIES:  pip install requests   (falls back to urllib if absent)

OPSEC: this issues HTTP GETs to the target's asset hosts — visible in access logs. Throttle threads,
use a real browser UA. Treat any recovered secret as a live credential (handle per ROE).

Authorized engagements only.
"""
import argparse
import json
import math
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

try:
    import requests
    HAVE_REQ = True
except ImportError:
    import urllib.request
    import ssl
    HAVE_REQ = False

UA = os.environ.get("HTTPX_UA",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0 Safari/537.36")

# Provider-specific high-confidence secret patterns.
SECRET_PATTERNS = {
    "aws_access_key":  r"\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b",
    "google_api":      r"\bAIza[0-9A-Za-z\-_]{35}\b",
    "slack_token":     r"\bxox[baprs]-[0-9A-Za-z-]{10,72}\b",
    "github_token":    r"\bgh[pousr]_[0-9A-Za-z]{36,255}\b",
    "stripe_live":     r"\bsk_live_[0-9a-zA-Z]{24,}\b",
    "stripe_pub":      r"\bpk_live_[0-9a-zA-Z]{24,}\b",
    "twilio_sid":      r"\bAC[a-f0-9]{32}\b",
    "sendgrid":        r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b",
    "jwt":             r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b",
    "private_key":     r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----",
    "firebase_url":    r"https://[a-z0-9\-]+\.firebaseio\.com",
    "google_oauth":    r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b",
}
# Generic key=value secrets (entropy-gated to suppress false positives).
GENERIC_RE = re.compile(
    r"""(?i)(?P<k>api[_-]?key|secret|client[_-]?secret|token|passwd|password|access[_-]?token|auth)
        ["'\s]*[:=]\s*["']?(?P<v>[A-Za-z0-9_\-./+]{16,80})["']?""",
    re.VERBOSE)
# Endpoint / path extraction (LinkFinder-style).
ENDPOINT_RE = re.compile(
    r"""(?:"|')
        (
          (?:/|\.\./|\./)[^"'><,;| *()(%%$^/\\\[\]][^"'><,;|()]{1,}      # relative paths
          |
          [a-zA-Z0-9_\-/.]+/[a-zA-Z0-9_\-/.]+(?:\.(?:json|php|asp|aspx|jsp|action|do)|/)  # api-ish
          |
          https?://[a-zA-Z0-9_.\-]+(?:/[^"'><,;|()]*)?                  # absolute urls
        )
        (?:"|')""",
    re.VERBOSE)
HOST_RE = re.compile(r"https?://([a-zA-Z0-9_.\-]+)")


def shannon(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def redact(s: str) -> str:
    if len(s) <= 8:
        return s[0] + "***"
    return s[:4] + "*" * (len(s) - 8) + s[-4:]


def fetch(url, timeout=12):
    try:
        if HAVE_REQ:
            r = requests.get(url, headers={"User-Agent": UA}, timeout=timeout)
            return r.text
        ctx = ssl.create_default_context()
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.read().decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return ""


def scan_js(url, fetch_maps):
    body = fetch(url)
    if not body:
        return url, [], set(), set()
    secrets = []

    for typ, pat in SECRET_PATTERNS.items():
        for m in re.finditer(pat, body):
            val = m.group(0)
            secrets.append({"js_url": url, "type": typ, "match": redact(val),
                            "entropy": round(shannon(val), 2),
                            "context": body[max(0, m.start() - 30):m.end() + 30].replace("\n", " ")})

    for m in GENERIC_RE.finditer(body):
        val = m.group("v")
        ent = shannon(val)
        # gate: require entropy and avoid obvious noise placeholders
        if ent >= 3.0 and val.lower() not in ("undefined", "null", "changeme", "example"):
            secrets.append({"js_url": url, "type": f"generic:{m.group('k').lower()}",
                            "match": redact(val), "entropy": round(ent, 2),
                            "context": body[max(0, m.start() - 20):m.end() + 10].replace("\n", " ")})

    endpoints = set()
    for m in ENDPOINT_RE.finditer(body):
        ep = m.group(1)
        if 1 < len(ep) < 200 and not ep.startswith(("data:", "blob:", "//fonts", "//www.w3")):
            endpoints.add(ep)

    hosts = set(HOST_RE.findall(body))

    if fetch_maps and not url.endswith(".map"):
        map_body = fetch(url + ".map", timeout=8)
        if map_body and '"sources"' in map_body:
            try:
                srcs = json.loads(map_body).get("sources", [])
                for s in srcs:
                    endpoints.add("[srcmap] " + s)
            except json.JSONDecodeError:
                pass

    return url, secrets, endpoints, hosts


def main():
    ap = argparse.ArgumentParser(description="JS endpoint + secret hunter")
    ap.add_argument("-l", "--list", required=True, help="file of .js URLs")
    ap.add_argument("-o", "--out", default="js_out")
    ap.add_argument("--threads", type=int, default=20)
    ap.add_argument("--maps", action="store_true", help="also fetch .map source maps")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    urls = [u.strip() for u in open(args.list, encoding="utf-8", errors="replace").read().splitlines()
            if u.strip() and urlparse(u.strip()).scheme in ("http", "https")]
    print(f"[*] scanning {len(urls)} JS files with {args.threads} threads", file=sys.stderr)

    all_eps, all_hosts = set(), set()
    sec_count = 0
    sec_path = os.path.join(args.out, "secrets.jsonl")
    with open(sec_path, "w", encoding="utf-8") as sf, \
         ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = [ex.submit(scan_js, u, args.maps) for u in urls]
        for fut in as_completed(futs):
            try:
                url, secrets, eps, hosts = fut.result()
            except Exception:  # noqa: BLE001
                continue
            all_eps |= eps
            all_hosts |= hosts
            for s in secrets:
                sf.write(json.dumps(s) + "\n")
                sec_count += 1
                print(f"[SECRET] {s['type']:24} {s['match']:20} ({s['js_url']})", file=sys.stderr)

    with open(os.path.join(args.out, "endpoints.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(all_eps)) + "\n")
    with open(os.path.join(args.out, "hosts.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(all_hosts)) + "\n")

    print(f"[+] endpoints: {len(all_eps)}  hosts: {len(all_hosts)}  secrets: {sec_count}",
          file=sys.stderr)
    print(f"[+] output in {args.out}/", file=sys.stderr)


if __name__ == "__main__":
    main()
