"""Tests for model_scorecard - Wilson-bounded, fail-closed model trust calibration.

Run: pytest tests/scripts/engine/test_model_scorecard.py
"""
import sys
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[3] / "engine"
sys.path.insert(0, str(ENGINE))

import pytest  # noqa: E402
import model_scorecard as ms  # noqa: E402


@pytest.fixture
def db(tmp_path):
    return str(tmp_path / "sc.sqlite")


# --------------------------------------------------------- Wilson math
def test_wilson_zero_samples_is_max_distrust():
    assert ms.wilson_upper(0, 0) == 1.0


def test_wilson_no_misses_still_has_upper_bound():
    # 0 misses in 20 -> upper bound is > 0 (we are not certain the true rate is 0)
    u = ms.wilson_upper(0, 20)
    assert 0 < u < 0.2


def test_wilson_small_n_wide_interval():
    # 0/3 has a much wider upper bound than 0/100
    assert ms.wilson_upper(0, 3) > ms.wilson_upper(0, 100)


def test_wilson_more_misses_higher_bound():
    assert ms.wilson_upper(5, 50) > ms.wilson_upper(1, 50)


def test_wilson_caps_at_one():
    assert ms.wilson_upper(10, 10) <= 1.0


# --------------------------------------------------------- record / counts
def test_record_and_counts(db):
    for _ in range(8):
        ms.record("opus", "finding-validator:PASS", overturned=False, path=db)
    ms.record("opus", "finding-validator:PASS", overturned=True, path=db)
    n, misses = ms.counts("opus", "finding-validator:PASS", path=db)
    assert n == 9 and misses == 1


def test_record_requires_fields(db):
    with pytest.raises(ValueError):
        ms.record("", "x", False, path=db)


# --------------------------------------------------------- trust gate (fail-closed)
def test_small_sample_not_trusted(db):
    # a perfect but tiny record must NOT be trusted (wide interval)
    for _ in range(5):
        ms.record("opus", "c", overturned=False, path=db)
    ok, why = ms.is_trusted("opus", "c", path=db)
    assert ok is False and "samples" in why


def test_clean_large_sample_trusted(db):
    # 0 misses needs ~73+ samples for the Wilson upper bound to drop below 5% (correct fail-closed)
    for _ in range(80):
        ms.record("opus", "c", overturned=False, path=db)
    ok, why = ms.is_trusted("opus", "c", path=db)
    assert ok is True, why


def test_one_miss_in_large_clean_record_revokes_or_keeps(db):
    # 1 miss in 40: upper bound ~ a few % - boundary. With 1/40 the upper bound exceeds 5%, so distrust.
    for _ in range(39):
        ms.record("opus", "c", overturned=False, path=db)
    ms.record("opus", "c", overturned=True, path=db)
    ok, _ = ms.is_trusted("opus", "c", max_rate=0.05, path=db)
    assert ok is False        # 1/40 Wilson upper > 5% -> fail closed


def test_high_miss_rate_not_trusted(db):
    for _ in range(30):
        ms.record("opus", "c", overturned=False, path=db)
    for _ in range(10):
        ms.record("opus", "c", overturned=True, path=db)
    ok, why = ms.is_trusted("opus", "c", path=db)
    assert ok is False and "miss-rate" in why


def test_unseen_cell_not_trusted(db):
    ok, _ = ms.is_trusted("never-seen", "never", path=db)
    assert ok is False        # zero samples -> never trusted


def test_min_n_threshold_respected(db):
    for _ in range(100):
        ms.record("opus", "c", overturned=False, path=db)
    assert ms.is_trusted("opus", "c", min_n=200, path=db)[0] is False  # still below min_n
    assert ms.is_trusted("opus", "c", min_n=50, path=db)[0] is True


# --------------------------------------------------------- stats + CLI
def test_stats(db):
    ms.record("opus", "a", overturned=False, path=db)
    ms.record("sonnet", "a", overturned=True, path=db)
    rows = ms.stats(path=db)
    assert {r["model"] for r in rows} == {"opus", "sonnet"}


def test_cli_record_and_trusted_exit_codes(db):
    for _ in range(80):
        assert ms.main(["record", "--model", "opus", "--class", "c", "--outcome", "correct", "--db", db]) == 0
    assert ms.main(["trusted", "--model", "opus", "--class", "c", "--db", db]) == 0   # trusted -> 0
    assert ms.main(["trusted", "--model", "new", "--class", "c", "--db", db]) == 3    # untrusted -> 3


# --------- PR-3b red-team regressions (raptor wjg32ea1y) ---------
def test_regression_nan_max_rate_fails_closed(db):
    # [0] a NaN threshold must NOT trust a 100%-miss cell (`x > nan` is always False)
    for _ in range(20):
        ms.record("bad", "c", overturned=True, path=db)
    ok, why = ms.is_trusted("bad", "c", max_rate=float("nan"), path=db)
    assert ok is False and "invalid max_rate" in why
    assert ms.main(["trusted", "--model", "bad", "--class", "c", "--max-rate", "nan", "--db", db]) == 2


def test_regression_max_rate_ge_one_fails_closed(db):
    # [1] max_rate >= 1.0 would universally trust; must be rejected
    for _ in range(20):
        ms.record("bad", "c", overturned=True, path=db)
    assert ms.is_trusted("bad", "c", max_rate=1.0, path=db)[0] is False
    assert ms.is_trusted("bad", "c", max_rate=2.0, path=db)[0] is False
    assert ms.main(["trusted", "--model", "bad", "--class", "c", "--max-rate", "1.0", "--db", db]) == 2


def test_regression_negative_min_n_fails_closed(db):
    for _ in range(80):
        ms.record("opus", "c", overturned=False, path=db)
    assert ms.is_trusted("opus", "c", min_n=0, path=db)[0] is False
    assert ms.main(["trusted", "--model", "opus", "--class", "c", "--min-n", "0", "--db", db]) == 2


# --------------------------------------------------------- Cohen's kappa (reliability signal)
def test_kappa_no_data_is_none():
    r = ms.cohens_kappa([])
    assert r["kappa"] is None and r["n"] == 0


def test_kappa_perfect_agreement_two_categories():
    # cohens_kappa is generic: it compares labels literally, so a shared label space is required.
    pairs = [("accept", "accept")] * 5 + [("reject", "reject")] * 5
    r = ms.cohens_kappa(pairs)
    assert r["p_o"] == 1.0
    assert abs(r["kappa"] - 1.0) < 1e-9
    assert r["interpretation"] == "almost perfect"


def test_agreement_kappa_canonicalizes_judge_dialects(db):
    # validator PASS vs checker ACCEPTED are the SAME decision -> perfect agreement after canon
    for _ in range(5):
        ms.record_pair("PASS", "ACCEPTED", path=db)
    for _ in range(5):
        ms.record_pair("KILL", "STALLED", path=db)
    r = ms.agreement_kappa(path=db)
    assert abs(r["kappa"] - 1.0) < 1e-9


def test_kappa_chance_level_is_near_zero():
    # raters independent: 2x2 balanced grid -> observed == expected agreement -> kappa ~ 0
    pairs = [("A", "A"), ("A", "B"), ("B", "A"), ("B", "B")]
    r = ms.cohens_kappa(pairs)
    assert abs(r["kappa"]) < 1e-9


def test_kappa_below_chance_is_negative_and_poor():
    # raters systematically disagree
    pairs = [("A", "B"), ("B", "A"), ("A", "B"), ("B", "A")]
    r = ms.cohens_kappa(pairs)
    assert r["kappa"] < 0
    assert "poor" in r["interpretation"]


def test_kappa_single_category_is_degenerate_not_perfect():
    # both raters only ever say ACCEPT -> chance agreement is total -> undefined, NOT 1.0
    r = ms.cohens_kappa([("ACCEPT", "ACCEPT")] * 10)
    assert r["kappa"] is None
    assert "degenerate" in r["interpretation"]


def test_kappa_ignores_none_labels():
    r = ms.cohens_kappa([("A", "A"), (None, "A"), ("A", None)])
    assert r["n"] == 1


def test_record_pair_and_agreement_kappa_roundtrip(db):
    for _ in range(4):
        ms.record_pair("PASS", "ACCEPTED", decision_class="exploit", path=db)
    for _ in range(4):
        ms.record_pair("KILL", "STALLED", decision_class="exploit", path=db)
    r = ms.agreement_kappa("exploit", path=db)
    assert r["n"] == 8
    assert abs(r["kappa"] - 1.0) < 1e-9


def test_agreement_kappa_scoped_by_class(db):
    ms.record_pair("PASS", "ACCEPTED", decision_class="web", path=db)
    ms.record_pair("KILL", "STALLED", decision_class="net", path=db)
    assert ms.agreement_kappa("web", path=db)["n"] == 1
    assert ms.agreement_kappa(None, path=db)["n"] == 2


def test_record_pair_requires_both_labels(db):
    import pytest
    with pytest.raises(ValueError):
        ms.record_pair("", "ACCEPTED", path=db)


def test_cli_record_pair_and_kappa(db, capsys):
    assert ms.main(["record-pair", "--validator", "PASS", "--checker", "ACCEPTED", "--db", db]) == 0
    assert ms.main(["record-pair", "--validator", "KILL", "--checker", "STALLED", "--db", db]) == 0
    capsys.readouterr()
    assert ms.main(["kappa", "--db", db]) == 0
    out = capsys.readouterr().out
    assert '"n": 2' in out
    assert '"kappa"' in out
