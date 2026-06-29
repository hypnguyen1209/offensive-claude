#!/usr/bin/env python3
"""
responder_loot_parser.py - Parse Responder/ntlmrelayx loot, dedupe, and
prepare hashes for hashcat + flag NTLMv1 (crackable to NT hash).

USAGE:
    # Parse a Responder log directory (default /usr/share/responder/logs)
    python3 responder_loot_parser.py --logs /usr/share/responder/logs

    # Parse a single hash file and emit hashcat-ready files
    python3 responder_loot_parser.py --file SMB-NTLMv2-SSP-10.0.0.5.txt --outdir ./loot

DEPENDENCIES: Python 3.8+ stdlib only.

Responder writes per-host files like:
    HTTP-NTLMv2-<ip>.txt, SMB-NTLMv1-<ip>.txt, MSSQL-NTLMv2-<ip>.txt ...
Each line is a captured hash in the standard "user::domain:..." NetNTLM format.

NTLMv1 (hashcat -m 5500) can be cracked to the NT hash instantly via
crack.sh / rainbow tables if the challenge was the magic 1122334455667788
(Responder default with --lm). This tool flags those for priority handling.
"""
import argparse
import os
import re
import sys
from collections import defaultdict

# hashcat mode mapping by captured-hash type
HASHCAT_MODES = {
    "NTLMv2": 5600,   # NetNTLMv2
    "NTLMv1": 5500,   # NetNTLMv1 (also crackable to NT hash via crack.sh)
}

# Responder default static challenge -> means NTLMv1 may be crack.sh-trivial
MAGIC_CHALLENGE = "1122334455667788"

LINE_RE = re.compile(r"^(?P<user>[^:]+)::(?P<domain>[^:]*):(?P<rest>.+)$")


def classify(line: str) -> str:
    """Return 'NTLMv1' or 'NTLMv2' based on field structure."""
    parts = line.strip().split(":")
    # NTLMv2: user::domain:serverchallenge:NTproofstr:blob  (>=6 fields)
    # NTLMv1: user::domain:LMresp:NTresp:challenge          (5 fields, hex)
    if len(parts) == 6:
        return "NTLMv2"
    if len(parts) == 5:
        return "NTLMv1"
    # ntlmrelayx multi-target format sometimes adds prefix; fall back on blob length
    return "NTLMv2" if len(parts) > 5 else "NTLMv1"


def iter_hash_files(logs_dir: str):
    for fn in os.listdir(logs_dir):
        if fn.endswith(".txt") and ("NTLM" in fn or "SSP" in fn):
            yield os.path.join(logs_dir, fn)


def parse_files(files):
    """Return dict keyed by (user, domain, type) -> hashline (deduped)."""
    seen = {}
    for path in files:
        try:
            with open(path, "r", errors="ignore") as fh:
                for raw in fh:
                    line = raw.strip()
                    if not line or "::" not in line:
                        continue
                    m = LINE_RE.match(line)
                    if not m:
                        continue
                    htype = classify(line)
                    key = (m.group("user").lower(), m.group("domain").lower(), htype)
                    # keep first occurrence (dedupe identical user/domain/type)
                    if key not in seen:
                        seen[key] = line
        except OSError as e:
            print(f"[!] skip {path}: {e}", file=sys.stderr)
    return seen


def main():
    ap = argparse.ArgumentParser(description="Parse Responder/ntlmrelayx loot.")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--logs", help="Responder logs directory")
    g.add_argument("--file", help="Single hash file")
    ap.add_argument("--outdir", default="./loot", help="Output directory")
    args = ap.parse_args()

    files = [args.file] if args.file else list(iter_hash_files(args.logs))
    if not files:
        print("[!] no hash files found", file=sys.stderr)
        sys.exit(1)

    seen = parse_files(files)
    os.makedirs(args.outdir, exist_ok=True)

    buckets = defaultdict(list)
    priority_v1 = []
    for (user, domain, htype), line in seen.items():
        buckets[htype].append(line)
        if htype == "NTLMv1" and MAGIC_CHALLENGE in line.replace(":", ""):
            priority_v1.append((user, domain, line))

    for htype, lines in buckets.items():
        mode = HASHCAT_MODES.get(htype, "?")
        out = os.path.join(args.outdir, f"hashes_{htype}.txt")
        with open(out, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        print(f"[+] {len(lines):4d} {htype} hashes -> {out}")
        print(f"    hashcat -m {mode} {out} /usr/share/wordlists/rockyou.txt -r best64.rule")

    if priority_v1:
        print(f"\n[!!] {len(priority_v1)} NTLMv1 with static challenge "
              f"({MAGIC_CHALLENGE}) -> submit to crack.sh for instant NT hash:")
        for user, domain, _ in priority_v1:
            print(f"     {domain}\\{user}")

    # unique account summary
    users = {(u, d) for (u, d, _) in seen}
    print(f"\n[=] {len(users)} unique accounts captured across {len(files)} files")


if __name__ == "__main__":
    main()
