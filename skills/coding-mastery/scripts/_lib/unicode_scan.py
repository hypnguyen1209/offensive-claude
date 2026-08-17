#!/usr/bin/env python3
"""unicode_scan.py - detect/strip invisible & bidi & ASCII-smuggling codepoints.

Untrusted content we ingest (proxy traffic via redact_headers, fetched pages, retrieved
artifacts) can carry codepoints that are invisible to a human reviewer but steer a model:
zero-width characters, bidirectional overrides (Trojan-Source), the Unicode Tag block
(U+E0000-E007F "ASCII smuggling"), invisible-math operators, and stray BOM/word-joiners.
This ports the taxonomy of ecc's check-unicode-safety.js.

  scan(text)  -> [Hit{codepoint, index, name}]  (empty = clean)
  strip(text) -> text with every dangerous codepoint removed

Legitimate content (accents, CJK, emoji) is NOT flagged - only the invisible/steering set.

CLI:
  unicode_scan.py --file path            # exit 1 if any dangerous codepoint, else 0
  unicode_scan.py --file path --write    # strip in place, exit 0
  unicode_scan.py --text "..."
"""
from __future__ import annotations

import argparse
import sys
import unicodedata
from dataclasses import dataclass
from typing import Optional

# explicit dangerous singletons
_DANGEROUS = {
    0x200B,  # zero-width space
    0x200C,  # zero-width non-joiner
    0x200D,  # zero-width joiner
    0x200E,  # left-to-right mark
    0x200F,  # right-to-left mark
    0x2060,  # word joiner
    0x2061,  # function application (invisible)
    0x2062,  # invisible times
    0x2063,  # invisible separator
    0x2064,  # invisible plus
    0xFEFF,  # zero-width no-break space / BOM
    0x061C,  # arabic letter mark
    0x115F,  # hangul choseong filler
    0x1160,  # hangul jungseong filler
    0x3164,  # hangul filler
    0xFFA0,  # halfwidth hangul filler
}
# dangerous ranges (start, end inclusive)
_DANGEROUS_RANGES = [
    (0x202A, 0x202E),  # bidi embeddings/overrides (LRE..RLO..PDF)
    (0x2066, 0x2069),  # bidi isolates (LRI..PDI)
    (0xE0000, 0xE007F),  # Unicode Tag block - ASCII smuggling
    (0xFE00, 0xFE0F),   # variation selectors (used to hide payloads)
]


def _is_dangerous(cp: int) -> bool:
    if cp in _DANGEROUS:
        return True
    for lo, hi in _DANGEROUS_RANGES:
        if lo <= cp <= hi:
            return True
    return False


@dataclass
class Hit:
    codepoint: str   # e.g. "U+200B"
    index: int       # 0-based position in the string
    name: str

    def to_dict(self) -> dict:
        return {"codepoint": self.codepoint, "index": self.index, "name": self.name}


def scan(text: Optional[str]) -> list[Hit]:
    if not text:
        return []
    hits: list[Hit] = []
    for i, ch in enumerate(text):
        cp = ord(ch)
        if _is_dangerous(cp):
            try:
                name = unicodedata.name(ch)
            except ValueError:
                name = "UNNAMED"
            hits.append(Hit(f"U+{cp:04X}", i, name))
    return hits


def strip(text: Optional[str]) -> str:
    if not text:
        return text or ""
    return "".join(ch for ch in text if not _is_dangerous(ord(ch)))


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Detect/strip invisible & smuggling codepoints.")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--file", help="scan this file")
    g.add_argument("--text", help="scan this literal text")
    p.add_argument("--write", action="store_true", help="strip dangerous codepoints in place (files only)")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    try:
        if args.file:
            with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        else:
            text = args.text
        hits = scan(text)
        if args.write and args.file:
            cleaned = strip(text)
            with open(args.file, "w", encoding="utf-8", newline="") as fh:
                fh.write(cleaned)
            return 0
        if args.json:
            import json
            print(json.dumps([h.to_dict() for h in hits]))
        else:
            for h in hits:
                print(f"{h.index}: {h.codepoint} {h.name}")
            if not hits:
                print("ok: no dangerous codepoints")
        return 1 if hits else 0
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
