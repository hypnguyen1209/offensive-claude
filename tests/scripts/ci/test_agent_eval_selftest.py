"""Tests for scripts/ci/agent_eval_selftest.py — the frozen-baseline judge self-test.

The self-test must pass on the real tree, must run in an ISOLATED db (never the operator's real
scorecard), and its --selftest CLI must exit 0. We also assert the isolation guard is real by
pointing the real db_path() at the same temp file the self-test would pick and confirming it refuses.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts" / "ci"))
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "engine"))

import agent_eval_selftest as aes  # noqa: E402
import model_scorecard as ms  # noqa: E402

_REPO = Path(__file__).resolve().parents[3]


def test_all_golden_scenarios_pass():
    cases = aes.run_selftest(_REPO)
    failed = [c for c in cases if not c.ok]
    assert not failed, [(c.name, c.detail) for c in failed]


def test_cli_selftest_exit_0():
    assert aes.main(["--selftest", "--root", str(_REPO)]) == 0


def test_requires_selftest_flag():
    # argparse .error() raises SystemExit(2)
    import pytest
    with pytest.raises(SystemExit):
        aes.main([])


def test_isolation_never_touches_real_scorecard(monkeypatch, tmp_path):
    # If the self-test's temp DB ever equals the real scorecard path, it must refuse (not record).
    # Simulate by forcing db_path() to whatever mkdtemp will produce is impractical; instead assert
    # that a normal run does NOT write to a scorecard placed at the default location.
    sentinel = tmp_path / "real_scorecard.sqlite"
    monkeypatch.setattr(ms, "db_path", lambda: str(sentinel))
    aes.run_selftest(_REPO)
    assert not sentinel.exists(), "self-test wrote to the (mocked) real scorecard DB"


def test_isolation_guard_refuses_on_collision(monkeypatch, tmp_path):
    # Force the self-test's temp DB to be exactly what db_path() reports -> guard must refuse.
    fixed = str(tmp_path)
    db = str(tmp_path / "scorecard.sqlite")
    monkeypatch.setattr(aes.tempfile, "mkdtemp", lambda prefix="": fixed)
    monkeypatch.setattr(aes.ms, "db_path", lambda: db)
    cases = aes.run_selftest(_REPO)
    iso = [c for c in cases if c.path == "isolation"]
    assert iso and iso[0].ok is False
    # and it must NOT have proceeded to record anything
    assert not any(c.path == "model_scorecard" for c in cases)
