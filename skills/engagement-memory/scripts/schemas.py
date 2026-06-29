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

import hashlib
import math
import re
import time
from typing import Optional

CURRENT_SCHEMA_VERSION = 1

SEVERITY_RANK = {"info": 0, "informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Lifecycle status (soft decay — knowledge is downranked/excluded, NEVER deleted).
STATUS = {"proposed", "active", "stale", "deprecated", "archived", "rejected"}
ACTIVE_STATUSES = {"active", "proposed"}          # what default recall returns
STATUS_TRUST = {"active": 3, "proposed": 2, "stale": 1, "deprecated": 0, "archived": 0, "rejected": -1}


class SchemaError(ValueError):
    """A record failed validation."""


def _now(ts: Optional[float]) -> float:
    return float(ts) if ts is not None else time.time()


def normalize_target(t: str) -> str:
    return (t or "").strip().lower().rstrip(".")


# A pattern stores a *reference* to evidence, never the secret itself. These catch obvious inline
# secrets so loot can't leak into the memory store (rotate exposed creds — do not just delete).
_SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),                 # PEM/SSH private key armor
    re.compile(r"[a-z][a-z0-9+.\-]*://[^/\s:@]+:[^/\s@]{3,}@"),           # URI userinfo (user:pass@host)
    re.compile(r"(?i)\b(gh[pousr]_|glpat-|whsec_|xox[baprs]-|sk_live_|sk_test_|rk_live_|sk-[A-Za-z0-9]|pk_live_)[A-Za-z0-9_\-]{10,}"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{20,}"),                            # Google API key
    re.compile(r"\bya29\.[0-9A-Za-z_\-]{10,}"),                          # Google OAuth token
    re.compile(r"hooks\.slack\.com/services/[A-Za-z0-9/]{10,}"),         # Slack webhook
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),                                 # AWS access-key ID
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+"),            # JWT
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=\-]{16,}"),              # bearer token value
]
# credential keyword followed by a secret-SHAPED value (length, no spaces) — not prose/placeholder
_KV_SECRET = re.compile(r"(?i)\b(pass(?:word|wd)?|secret|api[_-]?key|token|client[_-]?secret)\s*[:=]\s*([^\s,;'\"]{8,})")
_PLACEHOLDER = re.compile(r"(?i)^(x{3,}|\*{3,}|redacted|example[a-z0-9]*|changeme|placeholder|your[-_].+|<.*>|\.{3}|null|none|n/?a)$")
# A long CONTIGUOUS alnum run (no separators) is secret-shaped; paths/prose split into short words
# on /,-,_,. so they never form a 16+ run. This separates AWS-secret/base64/SSH-body from file paths.
_HIENT_CHUNK = re.compile(r"[A-Za-z0-9]{16,}")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def looks_like_secret(s: str) -> bool:
    """Best-effort inline-secret detector (errs toward catching, to keep loot out of the store)."""
    s = s or ""
    for p in _SECRET_PATTERNS:
        if p.search(s):
            return True
    m = _KV_SECRET.search(s)
    if m and not _PLACEHOLDER.match(m.group(2)):     # real value, not REDACTED/EXAMPLE/<...>
        return True
    for tok in _HIENT_CHUNK.findall(s):              # unprefixed high-entropy credential material
        if _entropy(tok) >= 3.6 and not _PLACEHOLDER.match(tok):
            return True
    return False


def make_pattern(target: str, vuln_class: str, *, cwe: str = "", attack_id: str = "",
                 technique: str = "", severity: str = "medium", cvss: Optional[float] = None,
                 tech_stack=None, evidence_ref: str = "", source: str = "",
                 status: str = "active", confidence: float = 1.0,
                 last_verified: Optional[float] = None, ttl_days: int = 0,
                 ts: Optional[float] = None) -> dict:
    t = _now(ts)
    rec = {
        "schema_version": CURRENT_SCHEMA_VERSION,
        "type": "pattern",
        "ts": t,
        "target": normalize_target(target),
        "tech_stack": sorted({str(s).strip().lower() for s in (tech_stack or []) if str(s).strip()}),
        "vuln_class": (vuln_class or "").strip().lower(),
        "cwe": str(cwe or "").upper().replace("CWE_", "CWE-") if cwe else "",
        "attack_id": str(attack_id or "").upper(),
        "technique": " ".join((technique or "").split()),     # collapse internal whitespace (matches key)
        "severity": (severity or "medium").strip().lower(),
        "cvss": float(cvss) if cvss is not None else None,
        "evidence_ref": str(evidence_ref or ""),
        "source": str(source or ""),
        "count": 1,
        "status": (status or "active").strip().lower(),
        "confidence": float(confidence),
        "last_verified": _now(last_verified) if last_verified is not None else t,
        "ttl_days": int(ttl_days),
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
    # lifecycle fields are OPTIONAL (older records predate them) — validate only if present
    if "status" in rec and rec.get("status") not in STATUS:
        raise SchemaError(f"invalid status: {rec.get('status')!r}")
    conf = rec.get("confidence")
    if conf is not None and (isinstance(conf, bool) or not isinstance(conf, (int, float)) or not (0.0 <= float(conf) <= 1.0)):
        raise SchemaError(f"confidence must be a number in 0-1: {conf!r}")
    lv = rec.get("last_verified")
    if lv is not None and (isinstance(lv, bool) or not isinstance(lv, (int, float))):
        raise SchemaError("last_verified must be a number or null")
    ttl = rec.get("ttl_days")
    if ttl is not None and (isinstance(ttl, bool) or not isinstance(ttl, int) or ttl < 0):
        raise SchemaError("ttl_days must be a non-negative int")
    for fld in ("evidence_ref", "source", "technique"):     # technique is free text -> can carry loot
        if looks_like_secret(str(rec.get(fld) or "")):
            raise SchemaError(f"{fld} looks like an inline secret — store a reference/path, "
                              "not the secret itself (rotate the exposed credential)")


def pattern_key(rec: dict) -> tuple:
    """Dedup identity: a technique against a target+class. Two records with the same key
    describe the same learned fact and are merged (count/last-seen)."""
    return (normalize_target(rec.get("target", "")),
            (rec.get("vuln_class") or "").lower(),
            " ".join((rec.get("technique") or "").lower().split()))   # collapse whitespace -> stable key


def pattern_id(rec: dict) -> str:
    """Stable short id derived from the dedup key (same key -> same id, append-only friendly)."""
    return hashlib.sha1("\x1f".join(pattern_key(rec)).encode("utf-8")).hexdigest()[:12]


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
    try:
        conf = float(rec.get("confidence", 1.0))
    except (TypeError, ValueError):
        conf = 1.0
    return (SEVERITY_RANK.get(rec.get("severity"), 0), cvss, conf, ts)


def merge(old: dict, new: dict) -> dict:
    """Combine two same-key records: keep the higher impact, bump count, keep latest ts."""
    keep = old if rank_score(old) >= rank_score(new) else new
    out = dict(keep)
    out["count"] = int(old.get("count", 1)) + int(new.get("count", 1))
    out["ts"] = max(float(old.get("ts") or 0), float(new.get("ts") or 0))
    out["tech_stack"] = sorted(set(old.get("tech_stack", [])) | set(new.get("tech_stack", [])))
    # the most RECENT status decision wins (so an explicit promote/deprecate is authoritative);
    # ties break to higher trust. confidence + verification recency accumulate.
    lo = float(old.get("last_verified") or old.get("ts") or 0)
    ln = float(new.get("last_verified") or new.get("ts") or 0)
    so, sn = old.get("status", "active"), new.get("status", "active")
    if ln > lo:
        out["status"] = sn
    elif lo > ln:
        out["status"] = so
    else:
        out["status"] = so if STATUS_TRUST.get(so, 2) >= STATUS_TRUST.get(sn, 2) else sn
    out["confidence"] = max(float(old.get("confidence", 1.0)), float(new.get("confidence", 1.0)))
    out["last_verified"] = max(lo, ln)
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
    for fld in ("note", "scope"):
        if looks_like_secret(str(rec.get(fld) or "")):
            raise SchemaError(f"audit.{fld} looks like an inline secret — log a reference, not the secret")


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
    if looks_like_secret(str(rec.get("notes") or "")):
        raise SchemaError("target_profile.notes looks like an inline secret — store a reference, not the secret")


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
