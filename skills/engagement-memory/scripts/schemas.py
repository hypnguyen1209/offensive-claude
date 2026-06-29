#!/usr/bin/env python3
"""schemas.py - typed records for the cross-engagement pattern memory.

The learning loop persists what WORKED so future engagements recall it instead of
re-deriving the same TTPs. Records are ranked by SEVERITY / CVSS (real impact) - never by
bug-bounty payout. Every record carries a schema_version so drift fails fast.

Record types:
  pattern         - a confirmed technique that worked against a (target, vuln_class, technique)
  target_profile  - durable facts about a target (tech stack, notable endpoints)
  audit           - append-only action log (rotated by discard; patterns are NOT)
"""
from __future__ import annotations

import time
from typing import Optional

CURRENT_SCHEMA_VERSION = 1

SEVERITY_RANK = {"info": 0, "informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class SchemaError(ValueError):
    """A record failed validation."""


def _now(ts: Optional[float]) -> float:
    return float(ts) if ts is not None else time.time()


def normalize_target(t: str) -> str:
    return (t or "").strip().lower().rstrip(".")


def make_pattern(target: str, vuln_class: str, *, cwe: str = "", attack_id: str = "",
                 technique: str = "", severity: str = "medium", cvss: Optional[float] = None,
                 tech_stack=None, evidence_ref: str = "", source: str = "",
                 ts: Optional[float] = None) -> dict:
    rec = {
        "schema_version": CURRENT_SCHEMA_VERSION,
        "type": "pattern",
        "ts": _now(ts),
        "target": normalize_target(target),
        "tech_stack": sorted({str(s).strip().lower() for s in (tech_stack or []) if str(s).strip()}),
        "vuln_class": (vuln_class or "").strip().lower(),
        "cwe": str(cwe or "").upper().replace("CWE_", "CWE-") if cwe else "",
        "attack_id": str(attack_id or "").upper(),
        "technique": (technique or "").strip(),
        "severity": (severity or "medium").strip().lower(),
        "cvss": float(cvss) if cvss is not None else None,
        "evidence_ref": str(evidence_ref or ""),
        "source": str(source or ""),
        "count": 1,
    }
    validate_pattern(rec)
    return rec


def validate_pattern(rec: dict) -> None:
    if not isinstance(rec, dict):
        raise SchemaError("pattern must be an object")
    if rec.get("type") != "pattern":
        raise SchemaError(f"not a pattern record: type={rec.get('type')!r}")
    sv = rec.get("schema_version")
    if isinstance(sv, bool) or not isinstance(sv, int) or sv != CURRENT_SCHEMA_VERSION:
        raise SchemaError(f"schema_version must be int {CURRENT_SCHEMA_VERSION}, got {sv!r}")
    if not rec.get("target") or not isinstance(rec.get("target"), str):
        raise SchemaError("pattern.target is required (string)")
    if not rec.get("vuln_class") or not isinstance(rec.get("vuln_class"), str):
        raise SchemaError("pattern.vuln_class is required (string)")
    if rec.get("severity") not in SEVERITY_RANK:
        raise SchemaError(f"invalid severity: {rec.get('severity')!r}")
    cvss = rec.get("cvss")
    if cvss is not None:
        if isinstance(cvss, bool) or not isinstance(cvss, (int, float)) or not (0.0 <= float(cvss) <= 10.0):
            raise SchemaError(f"cvss must be a number in 0-10 or null: {cvss!r}")
    ts = rec.get("ts")
    if ts is not None and (isinstance(ts, bool) or not isinstance(ts, (int, float))):
        raise SchemaError(f"ts must be a number or null: {ts!r}")
    count = rec.get("count", 1)
    if isinstance(count, bool) or not isinstance(count, int):
        raise SchemaError(f"count must be an int: {count!r}")
    ts_stack = rec.get("tech_stack", [])
    if not isinstance(ts_stack, list) or not all(isinstance(s, str) for s in ts_stack):
        raise SchemaError("tech_stack must be a list of strings")


def pattern_key(rec: dict) -> tuple:
    """Dedup identity: a technique against a target+class. Two records with the same key
    describe the same learned fact and are merged (count/last-seen)."""
    return (normalize_target(rec.get("target", "")),
            (rec.get("vuln_class") or "").lower(),
            (rec.get("technique") or "").lower())


def rank_score(rec: dict) -> tuple:
    """Sort key for recall: SEVERITY first (so a critical with no CVSS can't rank below a
    scored low), then CVSS, then recency. Sort DESCENDING. Coerces defensively."""
    try:
        cvss = float(rec.get("cvss") or 0.0)
    except (TypeError, ValueError):
        cvss = 0.0
    try:
        ts = float(rec.get("ts") or 0.0)
    except (TypeError, ValueError):
        ts = 0.0
    return (SEVERITY_RANK.get(rec.get("severity"), 0), cvss, ts)


def merge(old: dict, new: dict) -> dict:
    """Combine two same-key records: keep the higher impact, bump count, keep latest ts."""
    keep = old if rank_score(old) >= rank_score(new) else new
    out = dict(keep)
    out["count"] = int(old.get("count", 1)) + int(new.get("count", 1))
    out["ts"] = max(float(old.get("ts") or 0), float(new.get("ts") or 0))
    out["tech_stack"] = sorted(set(old.get("tech_stack", [])) | set(new.get("tech_stack", [])))
    return out
