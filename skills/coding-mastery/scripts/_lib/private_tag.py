#!/usr/bin/env python3
"""private_tag.py - strip operator-marked `<private>...</private>` spans before any persist (claude-mem).

An operator wraps engagement content that must NEVER cross a persistence boundary - into memory, the
finding store, or a report - in `<private>...</private>`. This is the LAST redaction gate, complementary
to secret_scan.py (which catches credential SHAPES the operator forgot): private_tag removes content the
operator DELIBERATELY marked, whatever its shape (a client name, a real target, a sensitive note).

Three rules that make it safe:
  * Fail-CLOSED on a malformed tag. An UNCLOSED `<private>` (open tag, no `</private>`) redacts to
    end-of-text - a truncated/garbled marker never leaks the tail it was meant to hide.
  * Absent != empty. `None` in -> `None` out (data was never there), `""` -> `""` (present but empty).
    A redacted span becomes a visible `[private omitted]` marker, so "redacted" is never silently
    conflated with "missing" downstream (claude-mem tag-stripping preserves this distinction).
  * Value-free. The marker carries no length/hash of what it replaced - the removed bytes leave no
    residue a reader (or a report) could reconstruct.

CLI:
  private_tag.py --text "keep <private>drop me</private> keep"     # prints stripped form
  private_tag.py --file notes.md --check                           # exit 1 if any private content
Exit: 0 clean, 1 (--check) private content present, 2 error.
"""
from __future__ import annotations

import argparse
import re
import sys
from typing import Optional

MARKER = "[private omitted]"

_SPAN = re.compile(r"<private>.*?</private>", re.IGNORECASE | re.DOTALL)   # closed span (non-greedy)
_OPEN = re.compile(r"<private>", re.IGNORECASE)
_CLOSE = re.compile(r"</private>", re.IGNORECASE)
_TRAILING_OPEN = re.compile(r"<private>.*\Z", re.IGNORECASE | re.DOTALL)   # unclosed -> to end


def has_private(text: Optional[str]) -> bool:
    """True if any `<private>` opening tag is present (closed or not)."""
    return bool(text) and bool(_OPEN.search(text))


def strip_private(text: Optional[str]) -> tuple[Optional[str], int]:
    """Return (clean_text, spans_removed). None passes through as None (absent, not redacted)."""
    if text is None:
        return None, 0
    n = 0

    def _sub(_m):
        nonlocal n
        n += 1
        return MARKER

    out = _SPAN.sub(_sub, text)
    if _OPEN.search(out):                       # an opening tag survived -> it has no matching close
        replaced = _TRAILING_OPEN.sub(MARKER, out)   # fail-closed: redact from the open tag to the end
        if replaced != out:
            n += 1
            out = replaced
    out = _CLOSE.sub("", out)                    # drop any stray unmatched closing tags
    return out, n


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(description="Strip <private>...</private> spans before persisting.")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--text")
    g.add_argument("--file")
    p.add_argument("--check", action="store_true", help="exit 1 if any private content is present")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    try:
        text = args.text
        if args.file:
            with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        if args.check:
            present = has_private(text)
            print("private content present" if present else "ok: no private content")
            return 1 if present else 0
        clean, n = strip_private(text)
        if args.json:
            import json
            print(json.dumps({"spans_removed": n, "clean": clean}))
        else:
            sys.stdout.write(clean if clean is not None else "")
        return 0
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
