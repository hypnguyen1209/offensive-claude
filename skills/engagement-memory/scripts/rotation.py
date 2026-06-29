#!/usr/bin/env python3
"""rotation.py - bounded growth for the memory store, without losing knowledge.

CRITICAL distinction:
- PATTERNS are COMPACTED, never blind-discarded. Compaction merges duplicate keys (keeping the
  highest-impact record and summed counts) and rewrites the file atomically. Aged patterns are
  exactly the knowledge we want to keep, so we never drop them by age/size.
- The AUDIT log (an action journal) MAY be discard-rotated by size - it is disposable.
"""
from __future__ import annotations

import json
import os
from typing import Optional

import schemas


def _atomic_write_lines(path: str, lines) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = f"{path}.tmp{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as fh:
        for ln in lines:
            fh.write(ln + "\n")
    os.replace(tmp, path)  # atomic, portable (no fcntl)


def compact(path: str) -> tuple:
    """Dedup-merge patterns by key and rewrite in place. Returns (before, after) line counts.
    Patterns are preserved (merged), not discarded."""
    if not os.path.isfile(path):
        return (0, 0)
    raw = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                schemas.validate_pattern(rec)
                raw.append(rec)
            except (ValueError, schemas.SchemaError):
                continue
    before = len(raw)
    by_key: dict = {}
    for rec in raw:
        k = schemas.pattern_key(rec)
        by_key[k] = schemas.merge(by_key[k], rec) if k in by_key else rec
    merged = sorted(by_key.values(), key=schemas.rank_score, reverse=True)
    _atomic_write_lines(path, [json.dumps(r) for r in merged])
    return (before, len(merged))


def maybe_gc(patterns_path: str, audit_path: Optional[str] = None, *,
             max_records: Optional[int] = None, max_bytes: int = 2_000_000) -> Optional[dict]:
    """Auto-compact the pattern store when it grows past a threshold. Safe to call after every
    record because compact() is LOSSLESS (merge, never discard). Only the disposable audit log
    discard-rotates. Returns a summary dict if it acted, else None."""
    if max_records is None:
        try:
            max_records = int(os.environ.get("ENGAGEMENT_DB_MAX_RECORDS", "5000"))
        except ValueError:
            max_records = 5000
    if not os.path.isfile(patterns_path):
        return None
    over = os.path.getsize(patterns_path) > max_bytes
    if not over:
        with open(patterns_path, "rb") as fh:
            over = sum(1 for _ in fh) > max_records
    if not over:
        return None
    before, after = compact(patterns_path)
    rotated = rotate_audit(audit_path) if audit_path else False
    return {"compacted": True, "before": before, "after": after, "audit_rotated": rotated}


def rotate_audit(path: Optional[str], max_bytes: int = 5_000_000, keep: int = 3) -> bool:
    """Discard-rotate a disposable audit log when it exceeds max_bytes. Returns True if rotated.
    Keeps `keep` historical files (path.1 .. path.keep); the oldest is discarded. Writes a
    retention-gap marker into the fresh log so the loss of disposable history is itself recorded."""
    if not path or not os.path.isfile(path) or os.path.getsize(path) <= max_bytes:
        return False
    oldest = f"{path}.{keep}"
    dropped = 0
    if os.path.exists(oldest):
        with open(oldest, "rb") as fh:
            dropped = sum(1 for _ in fh)
        os.remove(oldest)
    for i in range(keep - 1, 0, -1):
        src = f"{path}.{i}"
        if os.path.exists(src):
            os.replace(src, f"{path}.{i + 1}")
    os.replace(path, f"{path}.1")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(schemas.make_retention_gap("audit rotated", dropped)) + "\n")
    return True


def gc(patterns_path: str, audit_path: Optional[str] = None, *,
       audit_max_bytes: int = 5_000_000, audit_keep: int = 3) -> dict:
    before, after = compact(patterns_path)
    rotated = rotate_audit(audit_path, audit_max_bytes, audit_keep) if audit_path else False
    return {"patterns_before": before, "patterns_after": after, "audit_rotated": rotated}
