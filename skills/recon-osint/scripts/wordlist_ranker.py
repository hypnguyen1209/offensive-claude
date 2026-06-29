#!/usr/bin/env python3
"""wordlist_ranker.py - tier a password candidate list by real-world frequency.

For password-spray prep (network-attack / AD): the best spray candidates are NOT the most
common passwords (those are blocked/locked-out/noisy and burn the spray) - they are
org-specific and low-frequency. Given a frequency source (e.g. HIBP Pwned-Passwords counts,
or any "word:count" / "sha1:count" file), this tiers each candidate:

  generic    count > 1,000,000   -> SKIP   (lockout/noise risk, everyone's tried it)
  common     1,000 < count <= 1M  -> CAUTION
  sweet-spot 1 <= count <= 1,000  -> SPRAY  (real but uncommon - good signal)
  org-specific count == 0/unseen  -> SPRAY  (not in any breach corpus - likely org-built)

No network calls (feed it an offline counts file you already have). Pure + testable.

CLI:
  wordlist_ranker.py --wordlist cands.txt [--counts pwned.txt] [--tier spray] [--json]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from typing import Optional

GENERIC_MAX = 1_000_000
COMMON_MAX = 1_000
TIER_ORDER = {"org-specific": 0, "sweet-spot": 1, "common": 2, "generic": 3}
SPRAY_TIERS = {"org-specific", "sweet-spot"}


def tier_for(count: Optional[int]) -> str:
    """Tier a candidate from its breach-corpus occurrence count (None/0 = unseen)."""
    if not count:               # None or 0
        return "org-specific"
    if count <= COMMON_MAX:
        return "sweet-spot"
    if count <= GENERIC_MAX:
        return "common"
    return "generic"


def load_counts(path: str) -> dict:
    """Parse a 'key:count' or 'key count' frequency file. Keys are lowercased words or
    UPPERCASE sha1 hashes (HIBP range format). Returns {key: count}."""
    counts: dict[str, int] = {}
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            sep = ":" if ":" in line else (" " if " " in line else None)
            if not sep:
                continue
            key, _, val = line.partition(sep)
            key = key.strip()
            try:
                n = int(val.strip())
            except ValueError:
                continue
            # HIBP hashes are uppercase hex; plain words are matched lowercase
            counts[key.upper() if _looks_sha1(key) else key.lower()] = n
    return counts


def _looks_sha1(s: str) -> bool:
    return len(s) == 40 and all(c in "0123456789abcdefABCDEF" for c in s)


def lookup_count(word: str, counts: dict) -> Optional[int]:
    """Find a candidate's count by plaintext or by its SHA-1 (HIBP-style)."""
    if word.lower() in counts:
        return counts[word.lower()]
    sha1 = hashlib.sha1(word.encode("utf-8")).hexdigest().upper()
    return counts.get(sha1)


def rank(words, counts: dict) -> list:
    out = []
    for w in words:
        c = lookup_count(w, counts) if counts else None
        out.append({"word": w, "count": c, "tier": tier_for(c)})
    out.sort(key=lambda r: (TIER_ORDER[r["tier"]], r["count"] or 0))
    return out


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Tier a wordlist by breach frequency for spray prep.")
    p.add_argument("--wordlist", required=True)
    p.add_argument("--counts", help="offline frequency file (word:count or sha1:count)")
    p.add_argument("--tier", help="only output this tier (e.g. spray|sweet-spot|org-specific|generic)")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    try:
        with open(args.wordlist, "r", encoding="utf-8", errors="replace") as fh:
            words = [w.strip() for w in fh if w.strip()]
        counts = load_counts(args.counts) if args.counts else {}
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    ranked = rank(words, counts)
    if args.tier:
        want = SPRAY_TIERS if args.tier.lower() == "spray" else {args.tier.lower()}
        ranked = [r for r in ranked if r["tier"] in want]

    if args.json:
        print(json.dumps(ranked, indent=2))
    else:
        for r in ranked:
            c = "unseen" if r["count"] is None else r["count"]
            print(f"{r['tier']:12} {str(c):>10}  {r['word']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
