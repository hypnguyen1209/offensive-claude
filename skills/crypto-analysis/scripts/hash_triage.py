#!/usr/bin/env python3
"""
hash_triage.py - Identify password hashes, map to hashcat/john modes, grade KDF strength.

Heuristic identifier (regex + structure + length/charset) that, for each input line:
  - guesses the hash type(s)
  - emits the hashcat -m mode and john --format
  - grades KDF strength (fast hash vs memory-hard, bcrypt cost, PBKDF2 iterations)
  - prints a crack plan

Designed to seed an offline cracking workflow; do NOT use to spray live auth without ROE.

Usage:
  python3 hash_triage.py hashes.txt
  echo '$2b$12$...' | python3 hash_triage.py -

Dependencies: Python 3.8+ stdlib only.
Author: offensive-claude / crypto-analysis skill. Authorized engagements only.
"""
import argparse
import re
import sys

# (name, regex, hashcat_mode, john_format, speed_class)
SIGNATURES = [
    ("bcrypt",        re.compile(r"^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$"), 3200, "bcrypt", "slow"),
    ("sha512crypt",   re.compile(r"^\$6\$"), 1800, "sha512crypt", "slow"),
    ("sha256crypt",   re.compile(r"^\$5\$"), 7400, "sha256crypt", "slow"),
    ("md5crypt",      re.compile(r"^\$1\$"), 500, "md5crypt", "slow"),
    ("argon2",        re.compile(r"^\$argon2(id|i|d)\$"), 34000, "argon2", "memory-hard"),
    ("scrypt",        re.compile(r"^\$scrypt\$|^SCRYPT:"), 8900, "scrypt", "memory-hard"),
    ("pbkdf2-sha256", re.compile(r"^(sha256:)?\$?pbkdf2-sha256\$|^pbkdf2_sha256\$"), 10900, "PBKDF2-HMAC-SHA256", "slow"),
    ("phpass",        re.compile(r"^\$P\$|^\$H\$"), 400, "phpass", "slow"),
    ("NTLM",          re.compile(r"^[a-fA-F0-9]{32}$"), 1000, "nt", "fast"),
    ("MD5",           re.compile(r"^[a-fA-F0-9]{32}$"), 0, "raw-md5", "fast"),
    ("SHA1",          re.compile(r"^[a-fA-F0-9]{40}$"), 100, "raw-sha1", "fast"),
    ("SHA256",        re.compile(r"^[a-fA-F0-9]{64}$"), 1400, "raw-sha256", "fast"),
    ("SHA512",        re.compile(r"^[a-fA-F0-9]{128}$"), 1700, "raw-sha512", "fast"),
    ("NetNTLMv2",     re.compile(r"^[^:]+::[^:]*:[a-fA-F0-9]{16}:[a-fA-F0-9]{32}:.+$"), 5600, "netntlmv2", "fast"),
    ("Kerberoast-RC4", re.compile(r"^\$krb5tgs\$23\$"), 13100, "krb5tgs", "fast"),
    ("Kerberoast-AES", re.compile(r"^\$krb5tgs\$(17|18)\$"), 19700, "krb5tgs", "fast"),
    ("AS-REP",        re.compile(r"^\$krb5asrep\$23\$"), 18200, "krb5asrep", "fast"),
    ("JWT-HS",        re.compile(r"^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$"), 16500, "(N/A use jwt_forge.py)", "fast"),
    ("WPA-PBKDF2",    re.compile(r"^WPA\*"), 22000, "wpa-pbkdf2-pmkid+eapol", "slow"),
]

FAST_WARN = ("CWE-916: FAST hash used for passwords -> billions of guesses/sec on one "
             "RTX 4090 (e.g. ~300 GH/s NTLM). Trivially crackable.")


def grade_kdf(name, line):
    if name == "bcrypt":
        m = re.match(r"^\$2[abxy]\$(\d{2})\$", line)
        cost = int(m.group(1)) if m else 0
        if cost >= 12:
            return f"OK: bcrypt cost {cost} (>=12, 2025 baseline)"
        return f"WEAK: bcrypt cost {cost} (<12); hashcat -m3200 benchmarks at cost 5 -- raise to 12+"
    if name.startswith("pbkdf2"):
        m = re.search(r"\$(\d{3,})\$", line) or re.search(r":(\d{3,}):", line)
        it = int(m.group(1)) if m else 0
        if it >= 600000:
            return f"OK: PBKDF2 {it} iters (>=600k, OWASP 2023+)"
        return f"WEAK: PBKDF2 {it} iters (<600k OWASP baseline)"
    if name in ("argon2", "scrypt"):
        return "STRONG: memory-hard KDF (GPU-resistant)"
    if name in ("sha512crypt", "sha256crypt", "md5crypt", "phpass"):
        return "MODERATE: iterated unix-crypt; crackable with rules, prefer argon2id"
    return FAST_WARN


def identify(line):
    line = line.strip()
    if not line:
        return []
    hits = []
    for name, rx, mode, jf, speed in SIGNATURES:
        if rx.match(line):
            hits.append((name, mode, jf, speed))
    return hits


def main():
    ap = argparse.ArgumentParser(description="hash identifier + crack planner")
    ap.add_argument("infile", help="file of hashes, or - for stdin")
    args = ap.parse_args()

    fh = sys.stdin if args.infile == "-" else open(args.infile)
    for raw in fh:
        line = raw.rstrip("\r\n")
        if not line.strip():
            continue
        hits = identify(line)
        print(f"\n=== {line[:70]}{'...' if len(line) > 70 else ''}")
        if not hits:
            print("  [?] unknown format")
            continue
        # de-dup ambiguous 32-hex (NTLM vs MD5) -> report both
        printed = set()
        for name, mode, jf, speed in hits:
            key = (mode, jf)
            if key in printed:
                continue
            printed.add(key)
            print(f"  [{speed:11}] {name:15} hashcat -m {mode:<6} john --format={jf}")
        primary = hits[0]
        print(f"  KDF grade: {grade_kdf(primary[0], line)}")
        print(f"  plan: hashcat -m {primary[1]} hashes.txt wordlist.txt -r rules/best64.rule -O")


if __name__ == "__main__":
    main()
