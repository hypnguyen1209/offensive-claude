#!/usr/bin/env python3
"""
subdomain_takeover.py — Dangling-DNS / subdomain-takeover detector.

For each host: resolve CNAME chain, classify the third-party service, fetch the HTTP body, and
match against current "unclaimed resource" fingerprints. Also flags NS-delegation takeover (a
subdomain delegated to NS that no longer answer authoritatively) and emits S3 references for the
2024-2025 deleted-bucket supply-chain pivot.

USAGE:
  python3 subdomain_takeover.py -l subdomains.txt -o takeovers.jsonl [--threads 40] [--timeout 8]

DEPENDENCIES:  pip install dnspython requests
  (Pure-stdlib fallback used for HTTP if requests is missing; CNAME needs dnspython.)

OUTPUT (JSONL per vulnerable/suspicious host):
  {host, cname, service, fingerprint, severity, ns_delegation, s3_ref, evidence}

NOTE: Always re-verify against https://github.com/EdOverflow/can-i-take-over-xyz — provider reclaim
policy changes. Detection here is passive (one GET per host); CLAIMING a resource is out of scope of
this tool and must be ROE-approved.

Authorized engagements only.
"""
import argparse
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import dns.resolver
    import dns.exception
    HAVE_DNS = True
except ImportError:
    HAVE_DNS = False

try:
    import requests
    HAVE_REQ = True
except ImportError:
    import urllib.request
    import ssl
    HAVE_REQ = False

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0 Safari/537.36"

# (service, cname_regex, body_fingerprint, severity).  Verified-current high-signal set;
# the body fingerprint is what marks the resource as UNCLAIMED.
FINGERPRINTS = [
    ("aws-s3",        r"\.s3[.-].*amazonaws\.com",        r"NoSuchBucket",                       "high"),
    ("aws-s3-website",r"s3-website[.-].*amazonaws\.com",  r"NoSuchBucket|The specified bucket does not exist", "high"),
    ("heroku",        r"\.herokudns\.com|\.herokuapp\.com", r"No such app|herokucdn\.com/error", "high"),
    ("fastly",        r"\.fastly\.net",                   r"Fastly error: unknown domain",       "high"),
    ("github-pages",  r"\.github\.io",                    r"There isn't a GitHub Pages site here|404 - File not found", "medium"),
    ("azure",         r"\.azurewebsites\.net|\.cloudapp\.azure\.com|\.trafficmanager\.net|\.azureedge\.net", r"404 Web Site not found|The resource you are looking for has been removed", "high"),
    ("wix",           r"\.wixdns\.net",                   r"Error ConnectYourDomain occurred|wixErrorPagesApp", "medium"),
    ("shopify",       r"\.myshopify\.com",                r"Sorry, this shop is currently unavailable", "medium"),
    ("surge",         r"\.surge\.sh",                     r"project not found",                  "medium"),
    ("bitbucket",     r"\.bitbucket\.io",                 r"Repository not found",               "medium"),
    ("readme",        r"\.readme\.io",                    r"Project doesnt exist",               "low"),
    ("pantheon",      r"\.pantheonsite\.io",              r"The gods are wise|404 error unknown site", "medium"),
    ("ghost",         r"\.ghost\.io",                     r"The thing you were looking for is no longer here", "low"),
]
S3_RE = re.compile(r"[a-z0-9.\-]+\.s3[.-][a-z0-9.\-]*amazonaws\.com", re.I)


def resolve_chain(host):
    """Return (cname_target, ns_records, is_nxdomain)."""
    cname, ns, nx = "", [], False
    if not HAVE_DNS:
        return cname, ns, nx
    try:
        ans = dns.resolver.resolve(host, "CNAME", lifetime=6)
        cname = str(ans[0].target).rstrip(".")
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.NXDOMAIN:
        nx = True
    except dns.exception.DNSException:
        pass
    try:
        ans = dns.resolver.resolve(host, "NS", lifetime=6)
        ns = [str(r.target).rstrip(".") for r in ans]
    except dns.exception.DNSException:
        pass
    return cname, ns, nx


def http_body(host, timeout):
    # NOTE: TLS verification is intentionally disabled here. Dangling/unclaimed hosts (the exact
    # condition we detect) routinely serve expired, self-signed, or hostname-mismatched certs from
    # the orphaned third-party origin; with verification on we could not read the "unclaimed
    # resource" fingerprint body at all. We only READ a public error page — no secrets are sent.
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        try:
            if HAVE_REQ:
                r = requests.get(url, headers={"User-Agent": UA}, timeout=timeout,
                                 allow_redirects=True, verify=False)  # noqa: S501 (see note above)
                return r.text[:8000]
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return resp.read(8000).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            continue
    return ""


def check(host, timeout):
    host = host.strip().lower()
    if not host:
        return None
    cname, ns, nx = resolve_chain(host)
    body = http_body(host, timeout)
    result = None

    for service, cre, bre, sev in FINGERPRINTS:
        cname_match = bool(re.search(cre, cname, re.I)) if cname else False
        body_match = bool(re.search(bre, body, re.I)) if body else False
        # Strong signal: CNAME points at the service AND body shows the unclaimed fingerprint.
        if (cname_match and body_match) or (cname_match and nx) or body_match:
            result = {
                "host": host, "cname": cname, "service": service,
                "fingerprint": bre, "severity": sev if cname_match else "low",
                "ns_delegation": False, "s3_ref": None,
                "evidence": "cname+body" if (cname_match and body_match)
                            else ("cname+nxdomain" if (cname_match and nx) else "body-only"),
            }
            break

    # NS-delegation takeover: subdomain has NS records but resolves NXDOMAIN (dangling delegation).
    if not result and ns and nx:
        result = {"host": host, "cname": cname, "service": "ns-delegation",
                  "fingerprint": "NS records present but zone NXDOMAIN", "severity": "high",
                  "ns_delegation": True, "s3_ref": None, "evidence": "ns+nxdomain"}

    # Emit S3 references found in the body for the supply-chain pivot hunt (informational).
    s3 = S3_RE.findall(body) if body else []
    if s3 and not result:
        result = {"host": host, "cname": cname, "service": "s3-reference",
                  "fingerprint": "S3 bucket referenced in body", "severity": "info",
                  "ns_delegation": False, "s3_ref": sorted(set(s3)), "evidence": "s3-ref"}
    return result


def main():
    ap = argparse.ArgumentParser(description="Subdomain takeover detector")
    ap.add_argument("-l", "--list", required=True, help="file of subdomains (one per line)")
    ap.add_argument("-o", "--out", default="takeovers.jsonl")
    ap.add_argument("--threads", type=int, default=40)
    ap.add_argument("--timeout", type=int, default=8)
    args = ap.parse_args()

    if HAVE_REQ:
        import urllib3
        urllib3.disable_warnings()
    if not HAVE_DNS:
        print("[!] dnspython missing — CNAME/NS classification disabled "
              "(body-only matching). pip install dnspython", file=sys.stderr)

    hosts = [h for h in open(args.list, encoding="utf-8", errors="replace").read().splitlines() if h.strip()]
    print(f"[*] checking {len(hosts)} hosts with {args.threads} threads", file=sys.stderr)

    found = 0
    with open(args.out, "w", encoding="utf-8") as out, \
         ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = {ex.submit(check, h, args.timeout): h for h in hosts}
        for fut in as_completed(futs):
            try:
                r = fut.result()
            except Exception:  # noqa: BLE001
                continue
            if r:
                out.write(json.dumps(r) + "\n")
                out.flush()
                found += 1
                tag = "[TAKEOVER]" if r["severity"] in ("high", "medium") else "[INFO]"
                print(f"{tag} {r['host']} -> {r['service']} ({r['severity']})", file=sys.stderr)
    print(f"[+] {found} candidate(s) written to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
