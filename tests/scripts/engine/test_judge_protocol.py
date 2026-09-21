"""Tests for judge_protocol.py - discrete confidence buckets + formal LLM-judge protocol."""
import sys
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[3] / "engine"
sys.path.insert(0, str(ENGINE))

import judge_protocol as jp  # noqa: E402


# --------------------------------------------------------- discrete confidence
def test_five_buckets_strictly_descending():
    scores = [b["score"] for b in jp.CONFIDENCE_BUCKETS]
    assert scores == sorted(scores, reverse=True)
    assert len(scores) == 5
    assert len(set(scores)) == 5


def test_every_bucket_has_a_rubric_line():
    for b in jp.CONFIDENCE_BUCKETS:
        assert b["rubric"].strip()
        assert b["label"].isupper()


def test_bucket_for_exact_match_only():
    assert jp.bucket_for(0.95)["label"] == "CERTAIN"
    assert jp.bucket_for(0.90) is None          # between buckets -> not allowed
    assert jp.bucket_for("nonsense") is None


def test_normalize_confidence_by_score_and_label():
    assert jp.normalize_confidence(0.75) == "PROBABLE"
    assert jp.normalize_confidence("tentative") == "TENTATIVE"
    assert jp.normalize_confidence("AMBIGUOUS") == jp.AMBIGUOUS


def test_normalize_off_bucket_is_ambiguous_not_snapped():
    # a smuggled 0.9 must NOT read as almost-CERTAIN; it is AMBIGUOUS
    assert jp.normalize_confidence(0.9) == jp.AMBIGUOUS
    assert jp.normalize_confidence(0.99) == jp.AMBIGUOUS
    assert jp.normalize_confidence(None) == jp.AMBIGUOUS
    assert jp.normalize_confidence("high") == jp.AMBIGUOUS


# --------------------------------------------------------- rubric versioning / cache
def test_rubric_text_mentions_version_and_all_labels():
    txt = jp.rubric_text()
    assert jp.RUBRIC_VERSION in txt
    for b in jp.CONFIDENCE_BUCKETS:
        assert b["label"] in txt
    assert "EVD-" in txt


def test_fingerprint_is_stable_and_16_hex():
    fp = jp.rubric_fingerprint()
    assert fp == jp.rubric_fingerprint()
    assert len(fp) == 16
    int(fp, 16)


def test_cache_key_includes_rubric_fingerprint():
    k1 = jp.cache_key("F1", "abc")
    k2 = jp.cache_key("F1", "abc")
    assert k1 == k2
    assert jp.cache_key("F2", "abc") != k1     # finding id matters
    assert jp.cache_key("F1", "def") != k1     # artifact hash matters


def test_cache_key_changes_when_rubric_changes(monkeypatch):
    before = jp.cache_key("F1", "abc")
    monkeypatch.setattr(jp, "RUBRIC_VERSION", "9.9.9")
    assert jp.cache_key("F1", "abc") != before  # bumping the rubric invalidates the cache


# --------------------------------------------------------- verdict record contract
def test_valid_accept_record_passes():
    rec = {"decision": "PASS", "confidence": 0.95, "rubric_version": jp.RUBRIC_VERSION,
           "evidence": ["[EVD-001] cursor.execute at db.py:44"]}
    assert jp.validate_verdict_record(rec) == []


def test_accept_without_evidence_is_flagged():
    rec = {"decision": "CONFIRMED", "confidence": 0.95, "rubric_version": jp.RUBRIC_VERSION,
           "evidence": []}
    probs = jp.validate_verdict_record(rec)
    assert any("EVD-" in p for p in probs)


def test_reject_without_evidence_is_fine():
    rec = {"decision": "KILL", "confidence": 0.55, "rubric_version": jp.RUBRIC_VERSION,
           "evidence": []}
    assert jp.validate_verdict_record(rec) == []


def test_missing_fields_flagged():
    probs = jp.validate_verdict_record({"decision": "PASS"})
    assert any("confidence" in p for p in probs)
    assert any("rubric_version" in p for p in probs)


def test_stale_rubric_version_flagged():
    rec = {"decision": "KILL", "confidence": 0.55, "rubric_version": "0.0.1", "evidence": []}
    assert any("stale rubric_version" in p for p in jp.validate_verdict_record(rec))


def test_off_bucket_confidence_flagged():
    rec = {"decision": "KILL", "confidence": 0.42, "rubric_version": jp.RUBRIC_VERSION, "evidence": []}
    assert any("not a valid bucket" in p for p in jp.validate_verdict_record(rec))


def test_explicit_ambiguous_confidence_is_valid():
    # AMBIGUOUS is a legitimate confidence value, not an off-bucket violation
    rec = {"decision": "KILL", "confidence": "AMBIGUOUS", "rubric_version": jp.RUBRIC_VERSION,
           "evidence": []}
    assert jp.validate_verdict_record(rec) == []


# --------------------------------------------------------- calibration gate
def test_is_calibrated_requires_strict_separation():
    assert jp.is_calibrated([0.95, 0.85], [0.55, 0.65]) is True
    assert jp.is_calibrated([0.65], [0.65]) is False       # overlap (tie) -> not trustworthy
    assert jp.is_calibrated([0.65], [0.75]) is False       # inverted
    assert jp.is_calibrated([], [0.55]) is False           # no PASS evidence
    assert jp.is_calibrated([0.95], []) is False


def test_calibration_cases_are_well_formed():
    cc = jp.calibration_cases()
    assert len(cc["plant_pass"]) >= 2 and len(cc["plant_kill"]) >= 2
    # planted PASS cases cite EVD; planted KILL cases do not
    assert all(any("EVD-" in e for e in c["evidence"]) for c in cc["plant_pass"])
    assert all(c["evidence"] == [] for c in cc["plant_kill"])


# --------------------------------------------------------- grader attribution (cookbook: hold grader fixed)
def _base_verdict(**extra):
    v = {"decision": "PASS", "confidence": 0.95, "rubric_version": jp.RUBRIC_VERSION,
         "evidence": ["[EVD-001] proof"]}
    v.update(extra)
    return v


def test_grader_model_optional_absent_ok():
    # attribution is optional: a verdict without grader_model is still conformant
    assert jp.validate_verdict_record(_base_verdict()) == []


def test_grader_model_present_valid_ok():
    assert jp.validate_verdict_record(_base_verdict(grader_model="claude-opus-4-6")) == []


def test_grader_model_empty_or_nonstring_rejected():
    # present-but-empty looks attributed but isn't -> fail-closed
    assert jp.validate_verdict_record(_base_verdict(grader_model="   "))
    assert jp.validate_verdict_record(_base_verdict(grader_model=""))
    assert jp.validate_verdict_record(_base_verdict(grader_model=123))
