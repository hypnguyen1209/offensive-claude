#!/usr/bin/env python3
"""evidence_kit.py - typed, re-verifiable evidence objects for findings.

The problem this solves: today evidence is free-form files in a directory with no record of
WHERE each artifact came from and no way to prove it has not been tampered with since capture.
A stale or fabricated source slips through because "is this authentic and still true at the
source?" is never asked separately from "does the claim follow from it?".

This kit makes evidence a typed object with provenance and an integrity hash:

  EvidenceItem{ id (EVD-XXX), type, source, source_url, collected_at, content_sha256, raw_path, status }

`EvidenceStore.verify_all()` re-reads every item's local snapshot (`raw_path`), recomputes the
SHA-256, and stamps it VERIFIED (matches the recorded hash) or FAILED (missing / mismatch) -
tamper-evidence on the captured bytes. An optional `fetcher` callable re-fetches `source_url`
and checks the live source still matches, WITHOUT baking a network client into the default path
(scope/OPSEC stays the caller's choice; the default is offline and deterministic).

Fail-closed: anything we cannot positively verify is NOT 'verified'. No hash, missing file, or a
mismatch is FAILED; an item never silently passes. The downstream gate
(`validate_findings.py --evidence-store`) refuses a finding that cites a non-VERIFIED EVD id.

Pure stdlib (dataclasses + json + hashlib + datetime). No Pydantic / cloud deps.

CLI:
  evidence_kit.py add    --store evidence.json --type file --source "burp item 14" --file ./e.txt [--url ...]
  evidence_kit.py verify --store evidence.json [--json]      # exit 0 all VERIFIED, 1 any not, 2 error
  evidence_kit.py list   --store evidence.json [--json]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Callable, Optional

SCHEMA_VERSION = 1
UNVERIFIED = "UNVERIFIED"
VERIFIED = "VERIFIED"
FAILED = "FAILED"
_EVD_ID = re.compile(r"^EVD-[A-Za-z0-9_.\-]+$")
_CHUNK = 1 << 16


class EvidenceError(Exception):
    """Malformed store or item."""


def _utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def sha256_file(path: str) -> Optional[str]:
    """SHA-256 of a file, streamed. None if the file is missing/unreadable (fail-closed: the
    caller treats None as 'cannot verify', never as a pass)."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(_CHUNK), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, TypeError, ValueError):  # non-str path (type-confused store) fails CLOSED to None
        return None


@dataclass
class EvidenceItem:
    id: str
    type: str                      # file | http | commit | web | log | screenshot | other
    source: str                    # human description ("burp repeater item 14", "git show <sha>")
    content_sha256: str = ""       # hash recorded AT CAPTURE; verify_all re-checks against it
    raw_path: str = ""             # local snapshot of the captured bytes
    source_url: str = ""           # external provenance (CVE/advisory/commit URL), for re-fetch
    collected_at: str = ""
    status: str = UNVERIFIED
    note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "EvidenceItem":
        if not isinstance(d, dict):
            raise EvidenceError(f"evidence item must be an object, got {type(d).__name__}")
        eid = d.get("id")
        if not isinstance(eid, str) or not _EVD_ID.match(eid):
            raise EvidenceError(f"evidence id must match EVD-XXX, got {eid!r}")
        # type-validate every string field at LOAD so a well-formed-JSON but type-confused store
        # (e.g. raw_path:[...] or raw_path:true) is rejected here, not detonated at verify time.
        for k in ("type", "source", "content_sha256", "raw_path", "source_url", "collected_at", "status", "note"):
            v = d.get(k)
            if v is not None and not isinstance(v, str):
                raise EvidenceError(f"evidence field {k!r} must be a string, got {type(v).__name__}")
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        item = cls(**{k: v for k, v in d.items() if k in known})
        item.status = UNVERIFIED   # a loaded status is NEVER trusted; only verify_item may set VERIFIED
        return item


class EvidenceStore:
    def __init__(self, items: Optional[list] = None):
        self.items: list = list(items or [])

    # ------------------------------------------------------------------ io
    @classmethod
    def load(cls, path: str) -> "EvidenceStore":
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError as exc:
            raise EvidenceError(f"evidence store not found: {path}") from exc
        except json.JSONDecodeError as exc:
            raise EvidenceError(f"evidence store is not valid JSON: {exc}") from exc
        raw = data.get("evidence", data) if isinstance(data, dict) else data
        if not isinstance(raw, list):
            raise EvidenceError("evidence store must be a list (or {evidence:[...]})")
        items = [EvidenceItem.from_dict(it) for it in raw]
        seen = set()                      # reject duplicate ids at LOAD, CASE-INSENSITIVELY, so a
        for it in items:                  # FAILED 'EVD-ABC' can't launder a VERIFIED 'EVD-abc' twin
            key = it.id.upper()           # (validate_findings compares ids case-folded; the store
            if key in seen:               # is the single source of truth on id identity)
                raise EvidenceError(f"duplicate evidence id in store (case-insensitive): {it.id}")
            seen.add(key)
        return cls(items)

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        payload = {"schema_version": SCHEMA_VERSION, "evidence": [it.to_dict() for it in self.items]}
        tmp = f"{path}.tmp{os.getpid()}"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        os.replace(tmp, path)

    # ------------------------------------------------------------------ mutate
    def get(self, eid: str) -> Optional[EvidenceItem]:
        for it in self.items:
            if it.id == eid:
                return it
        return None

    def ids(self) -> set:
        return {it.id for it in self.items}

    def add(self, item: EvidenceItem) -> EvidenceItem:
        if not _EVD_ID.match(item.id or ""):
            raise EvidenceError(f"evidence id must match EVD-XXX, got {item.id!r}")
        if any(it.id.upper() == item.id.upper() for it in self.items):
            raise EvidenceError(f"duplicate evidence id (case-insensitive): {item.id}")
        if not item.collected_at:
            item.collected_at = _utcnow()
        if not item.content_sha256 and item.raw_path:
            h = sha256_file(item.raw_path)
            if h is None:
                raise EvidenceError(f"cannot hash raw_path (missing/unreadable): {item.raw_path}")
            item.content_sha256 = h
        item.status = UNVERIFIED
        self.items.append(item)
        return item

    # ------------------------------------------------------------------ verify
    def verify_item(self, item: EvidenceItem, fetcher: Optional[Callable[[str], bytes]] = None) -> EvidenceItem:
        """Re-verify ONE item. Local-snapshot integrity by default; if a fetcher is supplied and the
        item has a source_url, the live source is re-fetched and must ALSO match. Fail-closed."""
        # 1. there must be a recorded hash to verify against, and a local snapshot to verify
        if not isinstance(item.content_sha256, str) or not item.content_sha256:
            item.status = FAILED
            item.note = "no/invalid content_sha256 recorded - cannot verify integrity"
            return item
        if not isinstance(item.raw_path, str) or not item.raw_path:
            item.status = FAILED
            item.note = "no/invalid raw_path snapshot - nothing to re-hash"
            return item
        local = sha256_file(item.raw_path)
        if local is None:
            item.status = FAILED
            item.note = f"raw_path missing/unreadable: {item.raw_path}"
            return item
        if local != item.content_sha256:
            item.status = FAILED
            item.note = "local snapshot hash != recorded content_sha256 (tampered or wrong file)"
            return item
        # 2. optional live re-fetch of the external source
        if fetcher is not None and item.source_url:
            try:
                fetched = fetcher(item.source_url)
            except Exception as exc:                 # any fetch error => cannot confirm => FAILED
                item.status = FAILED
                item.note = f"source re-fetch failed: {exc}"
                return item
            if not isinstance(fetched, (bytes, bytearray)):
                item.status = FAILED
                item.note = "fetcher did not return bytes"
                return item
            if sha256_bytes(bytes(fetched)) != item.content_sha256:
                item.status = FAILED
                item.note = "live source no longer matches captured snapshot (source changed)"
                return item
        item.status = VERIFIED
        item.note = "snapshot integrity ok" + (" + source re-fetch ok" if (fetcher and item.source_url) else "")
        return item

    def verify_all(self, fetcher: Optional[Callable[[str], bytes]] = None) -> dict:
        counts = {VERIFIED: 0, FAILED: 0, UNVERIFIED: 0}
        for it in self.items:
            self.verify_item(it, fetcher=fetcher)
            counts[it.status] = counts.get(it.status, 0) + 1
        return counts

    def verified_ids(self) -> set:
        # fail-closed PER ID: an id counts as verified only if EVERY item carrying it is VERIFIED,
        # so a FAILED fabricated twin can never be laundered by a legitimate same-id sibling.
        by_id: dict = {}
        for it in self.items:
            by_id.setdefault(it.id, []).append(it.status)
        return {i for i, statuses in by_id.items() if statuses and all(s == VERIFIED for s in statuses)}


# --------------------------------------------------------------------------- CLI
def _cmd_add(args) -> int:
    store = EvidenceStore.load(args.store) if os.path.isfile(args.store) else EvidenceStore()
    item = EvidenceItem(id=args.id, type=args.type, source=args.source,
                        raw_path=args.file or "", source_url=args.url or "")
    store.add(item)
    store.save(args.store)
    print(f"added {item.id} ({item.type}) sha256={item.content_sha256[:16]}... -> {args.store}")
    return 0


def _cmd_verify(args) -> int:
    store = EvidenceStore.load(args.store)
    counts = store.verify_all()
    store.save(args.store)
    if args.json:
        print(json.dumps({"counts": counts, "items": [it.to_dict() for it in store.items]}, indent=2))
    else:
        for it in store.items:
            print(f"[{it.status:10}] {it.id:14} {it.type:10} {it.source[:40]:40} {it.note}")
        print("\nsummary: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    return 0 if counts.get(FAILED, 0) == 0 and counts.get(UNVERIFIED, 0) == 0 else 1


def _cmd_list(args) -> int:
    store = EvidenceStore.load(args.store)
    if args.json:
        print(json.dumps([it.to_dict() for it in store.items], indent=2))
    else:
        for it in store.items:
            print(f"{it.id:14} {it.status:10} {it.type:10} {it.source}")
    return 0


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(description="Typed re-verifiable evidence store.")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("add", help="add an evidence item")
    a.add_argument("--store", required=True)
    a.add_argument("--id", required=True, help="EVD-XXX")
    a.add_argument("--type", required=True)
    a.add_argument("--source", required=True)
    a.add_argument("--file", help="local snapshot path (hashed at capture)")
    a.add_argument("--url", help="external source URL (provenance)")

    v = sub.add_parser("verify", help="re-verify integrity of all items")
    v.add_argument("--store", required=True)
    v.add_argument("--json", action="store_true")

    ls = sub.add_parser("list", help="list items")
    ls.add_argument("--store", required=True)
    ls.add_argument("--json", action="store_true")

    args = p.parse_args(argv)
    try:
        return {"add": _cmd_add, "verify": _cmd_verify, "list": _cmd_list}[args.cmd](args)
    except EvidenceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # never fail-open
        print(f"error: unexpected failure: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
