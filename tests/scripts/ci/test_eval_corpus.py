"""Tests for scripts/ci/eval_corpus.py - the code-graded validator decision-quality eval.

Properties: (1) the shipped corpus scores a perfect exact-match against the deterministic validator
(it's a frozen labeled regression guard), (2) the fail-closed gate actually catches a false-CONFIRM and
a plain mismatch on a synthetic corpus, and (3) precision/recall math is correct.
"""
import json
import sys
from pathlib import Path

import pytest

_CI = Path(__file__).resolve().parents[3] / "scripts" / "ci"
sys.path.insert(0, str(_CI))

import eval_corpus as ec  # noqa: E402

_REPO = Path(__file__).resolve().parents[3]


# ------------------------------------------------------------------ shipped corpus
def test_shipped_corpus_is_perfect_and_green():
    assert ec.main([]) == 0                      # gate passes on the real tree


def test_shipped_corpus_no_false_confirms_and_full_match():
    res = ec.evaluate(ec._DEFAULT_CORPUS, ec._DEFAULT_CORPUS.parent / "evidence")
    assert res.ok is True
    assert res.false_confirms == []
    assert res.correct == res.total and res.total >= 20   # cookbook "higher volume" - a real set, not 4
    assert res.accuracy == 1.0


# ------------------------------------------------------------------ prf math
def test_prf_math():
    m = ec._prf(tp=8, fp=2, fn=0)
    assert m["precision"] == 0.8 and m["recall"] == 1.0 and m["support"] == 8
    z = ec._prf(0, 0, 0)
    assert z["precision"] == 0.0 and z["f1"] == 0.0


# ------------------------------------------------------------------ gate catches regressions
def _write_corpus(tmp_path, findings):
    d = tmp_path / "c"
    (d / "evidence").mkdir(parents=True)
    (d / "evidence" / "proof.txt").write_text("x", encoding="utf-8")
    (d / "corpus.json").write_text(json.dumps({"findings": findings}), encoding="utf-8")
    return d / "corpus.json", d / "evidence"


def test_gate_flags_false_confirm(tmp_path):
    # A bogus finding LABELLED as if it should be POSSIBLE, but we lie about expected to force the
    # dangerous case: validator says CONFIRMED (grounded SSRF w/ internal_response_read) while the
    # label claims POSSIBLE -> must be caught as BOTH a mismatch AND a false_confirm.
    corpus, ev = _write_corpus(tmp_path, [
        {"id": "X", "title": "SSRF", "cwe": "CWE-918", "severity": "high",
         "evidence": ["proof.txt"], "proof": {"internal_response_read": True}, "expected_tier": "POSSIBLE"},
    ])
    res = ec.evaluate(corpus, ev)
    assert res.ok is False
    assert res.false_confirms and res.false_confirms[0][0] == "X"
    assert ec.main(["--corpus", str(corpus), "--evidence", str(ev)]) == 1


def test_gate_flags_plain_mismatch(tmp_path):
    # validator REJECTS (ungrounded) but the label says CONFIRMED -> a mismatch (not a false-confirm).
    corpus, ev = _write_corpus(tmp_path, [
        {"id": "Y", "title": "RCE", "cwe": "CWE-78", "severity": "high",
         "evidence": [], "proof": {"command_output_captured": True}, "expected_tier": "CONFIRMED"},
    ])
    res = ec.evaluate(corpus, ev)
    assert res.ok is False and res.mismatches and not res.false_confirms


def test_missing_expected_tier_errors(tmp_path):
    corpus, ev = _write_corpus(tmp_path, [{"id": "Z", "title": "t", "evidence": ["proof.txt"]}])
    with pytest.raises(ValueError):
        ec.evaluate(corpus, ev)
