#!/usr/bin/env python3
"""
rsa_attack.py - RSA weak-key triage and recovery (CTF + key-hygiene auditing).

Pure-Python implementations (no Sage required) of:
  - Fermat factorization        (p ~= q, close primes; CVE-class: Boeck Fermat keys)
  - Wiener attack               (small private exponent d)
  - Common modulus attack       (same n, coprime e1/e2, same plaintext)
  - Hastad broadcast attack     (same m to e recipients, low e; CRT + integer e-th root)
  - Batch-GCD                   (corpus of keys sharing a prime)
  - Small-factor / trial sieve
  - ROCA fingerprint            (CVE-2017-15361 detector; full attack -> use roca/neca)
Optional SageMath hand-off for Coppersmith small_roots (partial-key) when --coppersmith.

Usage:
  python3 rsa_attack.py --pubkey key.pem --auto
  python3 rsa_attack.py --n N --e E --auto
  python3 rsa_attack.py --n N --e E --ct CIPHERTEXT_INT          # decrypt after factor
  python3 rsa_attack.py common-modulus --n N --e1 E1 --e2 E2 --c1 C1 --c2 C2
  python3 rsa_attack.py hastad --e 3 --pairs n1:c1 n2:c2 n3:c3
  python3 rsa_attack.py batch-gcd --moduli moduli.txt           # one decimal n per line
  python3 rsa_attack.py --pubkey key.pem --coppersmith --known-high 0xABCD...

Dependencies: Python 3.8+. PEM parsing uses 'cryptography' if present, else give --n/--e.
Author: offensive-claude / crypto-analysis skill. Authorized engagements only.
"""
import argparse
import sys
from math import isqrt, gcd


# ---------- key loading ----------
def load_pubkey(path):
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.x509 import load_pem_x509_certificate
        data = open(path, "rb").read()
        try:
            pub = load_pem_public_key(data)
        except Exception:
            pub = load_pem_x509_certificate(data).public_key()
        nums = pub.public_numbers()
        return nums.n, nums.e
    except ImportError:
        sys.exit("[-] 'cryptography' not installed; pass --n and --e manually.")


# ---------- factorization attacks ----------
def fermat(n, max_iter=2_000_000):
    a = isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_iter):
        b2 = a * a - n
        if b2 >= 0:
            b = isqrt(b2)
            if b * b == b2:
                p, q = a - b, a + b
                if p * q == n and p != 1:
                    return p, q
        a += 1
    return None


def small_factor(n, bound=1_000_000):
    if n % 2 == 0:
        return 2, n // 2
    i = 3
    while i < bound:
        if n % i == 0:
            return i, n // i
        i += 2
    return None


def batch_gcd(moduli):
    found = {}
    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            g = gcd(moduli[i], moduli[j])
            if 1 < g < moduli[i]:
                found[i] = g
                found[j] = g
    return found


# ---------- exponent / structural attacks ----------
def _egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = _egcd(b, a % b)
    return g, y, x - (a // b) * y


def wiener(e, n):
    """Recover small private exponent d via continued-fraction convergents of e/n."""
    def contfrac(x, y):
        while y:
            q = x // y
            yield q
            x, y = y, x - q * y

    def convergents(cf):
        num0, num1, den0, den1 = 0, 1, 1, 0
        for q in cf:
            num0, num1 = num1, q * num1 + num0
            den0, den1 = den1, q * den1 + den0
            yield num1, den1

    for k, d in convergents(contfrac(e, n)):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1  # p + q
        disc = s * s - 4 * n
        if disc >= 0:
            t = isqrt(disc)
            if t * t == disc and (s + t) % 2 == 0:
                return d
    return None


def common_modulus(c1, c2, e1, e2, n):
    g, a, b = _egcd(e1, e2)
    if g != 1:
        sys.exit("[-] e1 and e2 must be coprime for common-modulus attack.")
    inv_c1 = pow(c1, -1, n)
    inv_c2 = pow(c2, -1, n)
    m = 1
    m = (m * (pow(c1, a, n) if a >= 0 else pow(inv_c1, -a, n))) % n
    m = (m * (pow(c2, b, n) if b >= 0 else pow(inv_c2, -b, n))) % n
    return m


def integer_nth_root(x, n):
    if x < 0:
        return None
    lo, hi = 0, 1 << ((x.bit_length() // n) + 1)
    while lo <= hi:
        mid = (lo + hi) // 2
        p = mid ** n
        if p == x:
            return mid
        if p < x:
            lo = mid + 1
        else:
            hi = mid - 1
    return None


def hastad(pairs, e):
    """pairs: list of (n_i, c_i). Returns m if recoverable (CRT then integer e-th root)."""
    N = 1
    for n_i, _ in pairs:
        N *= n_i
    x = 0
    for n_i, c_i in pairs:
        Ni = N // n_i
        x = (x + c_i * Ni * pow(Ni, -1, n_i)) % N  # x == m^e mod N
    return integer_nth_root(x, e)


# ---------- ROCA fingerprint (CVE-2017-15361) ----------
def roca_fingerprint(n):
    """Detect Infineon RSALib structured primes. Positive => use roca/neca for full attack."""
    primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
              59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
              127, 131, 137, 139, 149, 151, 157, 163, 167]
    # The RSALib prime form is M-smooth; the discriminating test checks that 65537's
    # order divides the order of the modulus mod each small prime.
    for p in primes:
        if pow(65537, n % (p - 1) if p > 2 else 0, p) and (n % p) == 0:
            return False  # n divisible by small prime -> not ROCA, just weak
    # Heuristic discriminator from Nemec et al.: limited residue set mod small primes.
    suspicious = 0
    for p in primes:
        r = n % p
        # RSALib moduli have n mod p falling in a small generator subgroup
        order = 1
        g = 65537 % p
        val = g
        seen = {val}
        while val != 1 and order < p:
            val = (val * g) % p
            seen.add(val)
            order += 1
        if r % p in seen or r == 0:
            suspicious += 1
    return suspicious >= len(primes) - 4  # near-total match => likely ROCA


# ---------- driver ----------
def derive_private(p, q, e, n):
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    return d


def auto_attack(n, e, ct=None):
    print(f"[*] n bit-length: {n.bit_length()}, e: {e}")
    if e < 2 ** 20:
        print("[*] small e -> Hastad/cube-root may apply with multiple ciphertexts")

    print("[*] ROCA (CVE-2017-15361) fingerprint:", end=" ")
    try:
        print("LIKELY VULNERABLE -> run roca/neca" if roca_fingerprint(n) else "negative")
    except Exception as ex:
        print(f"check-error ({ex})")

    print("[*] trying small-factor sieve...")
    r = small_factor(n)
    if r:
        return _report_factors(*r, e, n, ct)

    print("[*] trying Fermat (close primes)...")
    r = fermat(n)
    if r:
        return _report_factors(*r, e, n, ct)

    print("[*] trying Wiener (small d)...")
    d = wiener(e, n)
    if d:
        print(f"[+] Wiener success! d = {d}")
        if ct is not None:
            print(f"[+] plaintext = {pow(ct, d, n)}")
        return True

    print("[-] no pure-Python attack succeeded. Try: RsaCtfTool, cado-nfs, or --coppersmith.")
    return False


def _report_factors(p, q, e, n, ct):
    print(f"[+] FACTORED: p={p}\n             q={q}")
    d = derive_private(p, q, e, n)
    print(f"[+] private exponent d = {d}")
    if ct is not None:
        print(f"[+] plaintext = {pow(ct, d, n)}")
    return True


def coppersmith_sage(n, e, known_high):
    """Emit/execute a SageMath small_roots stub for partial-key recovery."""
    sage_code = f"""
n = {n}
e = {e}
known = {known_high}   # known high bits of p
F.<x> = PolynomialRing(Zmod(n))
# p = known + x ; find small root x s.t. (known + x) | n  (Coppersmith)
unknown_bits = {n.bit_length() // 2} - known.nbits()
f = known + x
f = f.monic()
roots = f.small_roots(X=2**unknown_bits, beta=0.4)
print("roots:", roots)
"""
    print("[*] Run the following with SageMath (sage rsa_cs.sage):")
    print(sage_code)


def main():
    ap = argparse.ArgumentParser(description="RSA weak-key triage/recovery")
    ap.add_argument("mode", nargs="?", default="auto",
                    choices=["auto", "common-modulus", "hastad", "batch-gcd"])
    ap.add_argument("--pubkey")
    ap.add_argument("--n", type=int)
    ap.add_argument("--e", type=int)
    ap.add_argument("--ct", type=int, help="ciphertext as integer")
    ap.add_argument("--auto", action="store_true")
    ap.add_argument("--coppersmith", action="store_true")
    ap.add_argument("--known-high", type=lambda x: int(x, 0))
    # common-modulus
    ap.add_argument("--e1", type=int); ap.add_argument("--e2", type=int)
    ap.add_argument("--c1", type=int); ap.add_argument("--c2", type=int)
    # hastad
    ap.add_argument("--pairs", nargs="+", help="n:c pairs for Hastad")
    # batch-gcd
    ap.add_argument("--moduli", help="file: one decimal modulus per line")
    args = ap.parse_args()

    if args.mode == "common-modulus":
        m = common_modulus(args.c1, args.c2, args.e1, args.e2, args.n)
        print(f"[+] recovered m = {m}")
        return

    if args.mode == "hastad":
        pairs = []
        for pr in args.pairs:
            n_s, c_s = pr.split(":")
            pairs.append((int(n_s), int(c_s)))
        m = hastad(pairs, args.e)
        print(f"[+] recovered m = {m}" if m else "[-] Hastad failed (need e coprime moduli)")
        return

    if args.mode == "batch-gcd":
        moduli = [int(line) for line in open(args.moduli) if line.strip()]
        found = batch_gcd(moduli)
        if found:
            for idx, p in found.items():
                print(f"[+] modulus #{idx} shares prime {p}; q = {moduli[idx] // p}")
        else:
            print("[-] no shared primes")
        return

    # auto
    if args.pubkey:
        n, e = load_pubkey(args.pubkey)
    else:
        n, e = args.n, args.e
    if n is None or e is None:
        sys.exit("[-] provide --pubkey or --n/--e")

    if args.coppersmith:
        coppersmith_sage(n, e, args.known_high or 0)
        return
    auto_attack(n, e, args.ct)


if __name__ == "__main__":
    main()
