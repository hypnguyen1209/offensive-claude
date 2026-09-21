#!/usr/bin/env python3
"""judge_protocol.py - single source of truth for the LLM-judge protocol (ponytail judge.py + graphify).

Two ideas, one module so they can never drift apart:

1. DISCRETE confidence (graphify): grounding confidence is one of five named buckets, never a
   free-floating 0-1 number. Each bucket has a one-line rubric. If NONE fit, the claim is AMBIGUOUS -
   you do NOT invent a score. This is the *grounding* axis (how well the claim is tied to the artifact),
   orthogonal to the impact tier ([CONFIRMED]/[POSSIBLE]/[INFO]).

2. A FORMAL judge protocol (ponytail): every verdict is produced under pinned, reproducible decoding
   (temperature 0), carries the VERSIONED rubric it was judged against, must cite re-verifiable
   [EVD-XXX] evidence for any accept, and is cached under a key that includes the rubric fingerprint -
   so bumping the rubric invalidates every stale verdict rather than serving a verdict judged by an
   old standard.

Bump RUBRIC_VERSION (and the buckets/text below) together whenever the standard changes; the
fingerprint changes with it and old cached verdicts fall out. Pure stdlib.
"""
from __future__ import annotations

import hashlib
import json
from typing import Optional

# Bump this (semver) whenever CONFIDENCE_BUCKETS or the protocol text below changes. The fingerprint
# derives from the actual content, so a forgotten bump is caught by rubric_fingerprint() drifting.
RUBRIC_VERSION = "1.0.0"

AMBIGUOUS = "AMBIGUOUS"

# Discrete grounding-confidence buckets, strongest first. `score` is the canonical value a judge emits;
# `label` names it; `rubric` is the one-line test for assigning it. If no bucket's rubric holds, the
# judge emits AMBIGUOUS and stops - it must not interpolate a number between buckets.
CONFIDENCE_BUCKETS = [
    {"score": 0.95, "label": "CERTAIN",
     "rubric": "A direct quote from the artifact proves the claim; no inference."},
    {"score": 0.85, "label": "STRONG",
     "rubric": "Stated in the artifact but needs trivial composition of two direct quotes."},
    {"score": 0.75, "label": "PROBABLE",
     "rubric": "Rests on an assumption the artifact explicitly supports."},
    {"score": 0.65, "label": "TENTATIVE",
     "rubric": "A flagged inference from surrounding code; not directly stated."},
    {"score": 0.55, "label": "WEAK",
     "rubric": "Plausible but unverified - the weakest defensible claim."},
]

_VALID_SCORES = {b["score"] for b in CONFIDENCE_BUCKETS}
_LABEL_BY_SCORE = {b["score"]: b["label"] for b in CONFIDENCE_BUCKETS}

# Pinned decoding for reproducibility. A judge run outside these settings is not comparable and its
# verdict must not be cached as if it were.
JUDGE_DECODING = {"temperature": 0.0, "top_p": 1.0}

# Machine-checkable protocol invariants a verdict record must satisfy (see validate_verdict_record).
REQUIRED_VERDICT_FIELDS = ("decision", "confidence", "rubric_version", "evidence")
# Optional attribution fields (recognized, validated-if-present, not required). `grader_model` records
# WHICH model issued the verdict so scores stay comparable across models (the cookbook agentic-search
# "hold the grader fixed" discipline) and feed the right model_scorecard cell. Kept optional so the
# stable verdict protocol is not broken for existing producers; model_scorecard already keys cells by model.
ATTRIBUTION_FIELDS = ("grader_model",)
ACCEPT_DECISIONS = {"PASS", "ACCEPTED", "CONFIRMED"}


def bucket_for(score) -> Optional[dict]:
    """Return the bucket whose score EXACTLY matches, else None (an off-bucket number is not allowed)."""
    try:
        s = round(float(score), 2)
    except (TypeError, ValueError):
        return None
    for b in CONFIDENCE_BUCKETS:
        if b["score"] == s:
            return b
    return None


def normalize_confidence(value) -> str:
    """Map a judge's emitted confidence onto a bucket LABEL, or AMBIGUOUS. Fail-closed: any value that
    is not exactly one of the five bucket scores (or their label) is AMBIGUOUS - no snapping, no
    interpolation, so a judge cannot smuggle in a 0.9 that reads as 'almost CERTAIN'."""
    if isinstance(value, str):
        v = value.strip().upper()
        if v == AMBIGUOUS:
            return AMBIGUOUS
        for b in CONFIDENCE_BUCKETS:
            if v == b["label"]:
                return b["label"]
        return AMBIGUOUS
    b = bucket_for(value)
    return b["label"] if b else AMBIGUOUS


def rubric_text() -> str:
    """The exact, versioned rubric string emitted into each verdict record and hashed for the cache
    key. Deterministic: same version -> same bytes."""
    lines = [f"LLM-JUDGE RUBRIC v{RUBRIC_VERSION}",
             f"decoding: temperature={JUDGE_DECODING['temperature']} top_p={JUDGE_DECODING['top_p']}",
             "grounding confidence (pick exactly one; if none fit -> AMBIGUOUS, do not invent a score):"]
    for b in CONFIDENCE_BUCKETS:
        lines.append(f"  {b['score']:.2f} {b['label']}: {b['rubric']}")
    lines.append("accept (PASS/CONFIRMED) requires >=1 re-verifiable [EVD-XXX] citation.")
    return "\n".join(lines)


def rubric_fingerprint() -> str:
    """Content hash of (version + buckets + decoding + text). The verdict cache key MUST include this,
    so any change to the standard invalidates every verdict judged under the old one."""
    blob = json.dumps({
        "version": RUBRIC_VERSION, "buckets": CONFIDENCE_BUCKETS,
        "decoding": JUDGE_DECODING, "text": rubric_text(),
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:16]


def cache_key(finding_id: str, artifact_hash: str) -> str:
    """Verdict-cache key bound to the rubric fingerprint - bump the rubric and every stale verdict
    misses the cache and is re-judged."""
    raw = f"{rubric_fingerprint()}\0{finding_id}\0{artifact_hash}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def validate_verdict_record(record) -> list:
    """Return a list of protocol violations (empty == conformant). Enforces: required fields present,
    confidence is a real bucket-or-AMBIGUOUS, rubric_version matches the current standard, and any
    ACCEPT decision cites at least one [EVD-XXX]."""
    problems = []
    if not isinstance(record, dict):
        return ["record is not an object"]
    for f in REQUIRED_VERDICT_FIELDS:
        if f not in record:
            problems.append(f"missing required field: {f}")
    # Attribution fields are optional, but if present must be meaningful (a blank grader_model is worse
    # than none — it looks attributed but isn't). Fail-closed on an empty/non-string value.
    for f in ATTRIBUTION_FIELDS:
        if f in record and (not isinstance(record[f], str) or not record[f].strip()):
            problems.append(f"attribution field {f!r} present but empty/non-string")
    if "confidence" in record and normalize_confidence(record["confidence"]) == AMBIGUOUS \
            and str(record.get("confidence", "")).strip().upper() != AMBIGUOUS:
        problems.append(f"confidence {record['confidence']!r} is not a valid bucket (must be one of "
                        f"{sorted(_VALID_SCORES)} / a bucket label / AMBIGUOUS)")
    if record.get("rubric_version") not in (None, RUBRIC_VERSION) and "rubric_version" in record:
        problems.append(f"stale rubric_version {record.get('rubric_version')!r} != {RUBRIC_VERSION}")
    decision = str(record.get("decision", "")).strip().upper()
    if decision in ACCEPT_DECISIONS:
        ev = record.get("evidence") or []
        cites = [e for e in ev if isinstance(e, str) and "EVD-" in e]
        if not cites:
            problems.append(f"{decision} verdict must cite >=1 re-verifiable [EVD-XXX] evidence id")
    return problems


def is_calibrated(pass_scores, kill_scores) -> bool:
    """Judge calibration gate (ponytail): a batch is TRUSTWORTHY only if EVERY planted-PASS score
    ranks STRICTLY above EVERY planted-KILL score. Any overlap -> not trustworthy (the judge cannot
    separate real from bogus, so its verdicts on this batch are void). Empty either side -> not
    calibrated (no evidence of separation)."""
    ps = [x for x in (pass_scores or []) if isinstance(x, (int, float))]
    ks = [x for x in (kill_scores or []) if isinstance(x, (int, float))]
    if not ps or not ks:
        return False
    return min(ps) > max(ks)


def calibration_cases() -> dict:
    """Planted cases a live judge must rank correctly. Two obvious PASS (clearly grounded+cited) and
    two obvious KILL (unfalsifiable / no evidence). A judge that cannot rank these is not trusted."""
    return {
        "plant_pass": [
            {"id": "CAL-P1", "claim": "execute() runs attacker-controlled SQL",
             "evidence": ["[EVD-001] cursor.execute(f\"...{request.args['q']}...\") at db.py:44"]},
            {"id": "CAL-P2", "claim": "os.system runs the unsanitized filename",
             "evidence": ["[EVD-002] os.system('convert ' + upload.name) at img.py:12"]},
        ],
        "plant_kill": [
            {"id": "CAL-K1", "claim": "the app is probably insecure somewhere", "evidence": []},
            {"id": "CAL-K2", "claim": "this could be exploitable under some config", "evidence": []},
        ],
    }
