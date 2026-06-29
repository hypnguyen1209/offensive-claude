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


# --------------------------------------------------------------------------- audit records
# An audit row = one engagement memory action. Disposable (rotated by discard), separate from
# patterns. Provides ROE/attribution evidence and makes silent skips ("denial") visible.
AUDIT_ACTIONS = {"read", "write", "delete", "generate", "admin"}
AUDIT_OUTCOMES = {"success", "error", "denial"}


def make_audit(action_class: str, tool: str, *, target: Optional[str] = None,
               outcome: str = "success", dry_run: bool = False, duration_ms=None,
               scope: str = "", note: str = "", ts: Optional[float] = None) -> dict:
    rec = {
        "schema_version": CURRENT_SCHEMA_VERSION,
        "type": "audit",
        "ts": _now(ts),
        "action_class": (action_class or "").strip().lower(),
        "tool": str(tool or ""),
        "target": normalize_target(target) if target else None,
        "outcome": (outcome or "success").strip().lower(),
        "dry_run": bool(dry_run),
        "duration_ms": (int(duration_ms) if duration_ms is not None else None),
        "scope": str(scope or ""),
        "note": str(note or ""),
    }
    validate_audit(rec)
    return rec


def validate_audit(rec: dict) -> None:
    if not isinstance(rec, dict) or rec.get("type") != "audit":
        raise SchemaError(f"not an audit record: type={rec.get('type')!r}")
    sv = rec.get("schema_version")
    if isinstance(sv, bool) or not isinstance(sv, int) or sv != CURRENT_SCHEMA_VERSION:
        raise SchemaError(f"audit schema_version must be int {CURRENT_SCHEMA_VERSION}, got {sv!r}")
    if rec.get("action_class") not in AUDIT_ACTIONS:
        raise SchemaError(f"invalid audit action_class: {rec.get('action_class')!r}")
    if rec.get("outcome") not in AUDIT_OUTCOMES:
        raise SchemaError(f"invalid audit outcome: {rec.get('outcome')!r}")
    if not isinstance(rec.get("dry_run"), bool):
        raise SchemaError("audit.dry_run must be a bool")
    dm = rec.get("duration_ms")
    if dm is not None and (isinstance(dm, bool) or not isinstance(dm, int)):
        raise SchemaError("audit.duration_ms must be an int or null")


# --------------------------------------------------------------------------- target profiles
# Durable facts about a target (tech stack, notable endpoints) — the third tier above
# raw observations and confirmed patterns. Kept in the pattern store but a distinct type, so
# pattern recall never mixes them in.
def make_target_profile(target: str, *, tech_stack=None, endpoints=None,
                        notes: str = "", ts: Optional[float] = None) -> dict:
    rec = {
        "schema_version": CURRENT_SCHEMA_VERSION,
        "type": "target_profile",
        "ts": _now(ts),
        "target": normalize_target(target),
        "tech_stack": sorted({str(s).strip().lower() for s in (tech_stack or []) if str(s).strip()}),
        "endpoints": [str(e).strip() for e in (endpoints or []) if str(e).strip()],
        "notes": str(notes or ""),
    }
    validate_target_profile(rec)
    return rec


def validate_target_profile(rec: dict) -> None:
    if not isinstance(rec, dict) or rec.get("type") != "target_profile":
        raise SchemaError(f"not a target_profile record: type={rec.get('type')!r}")
    sv = rec.get("schema_version")
    if isinstance(sv, bool) or not isinstance(sv, int) or sv != CURRENT_SCHEMA_VERSION:
        raise SchemaError(f"target_profile schema_version must be int {CURRENT_SCHEMA_VERSION}, got {sv!r}")
    if not rec.get("target") or not isinstance(rec.get("target"), str):
        raise SchemaError("target_profile.target is required (string)")
    for k in ("tech_stack", "endpoints"):
        v = rec.get(k, [])
        if not isinstance(v, list) or not all(isinstance(s, str) for s in v):
            raise SchemaError(f"target_profile.{k} must be a list of strings")


def make_retention_gap(reason: str, dropped: int, ts: Optional[float] = None) -> dict:
    """A marker written into the audit log right before it is discard-rotated, so the rotation
    (loss of disposable history) is itself recorded."""
    return {
        "schema_version": CURRENT_SCHEMA_VERSION,
        "type": "retention_gap",
        "ts": _now(ts),
        "reason": str(reason or ""),
        "dropped": int(dropped),
    }
