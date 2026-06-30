"""Tests for the bounded generator<->checker rebuttal loop.

Run: pytest tests/scripts/engine/test_rebuttal.py
"""
import sys
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[3] / "engine"
sys.path.insert(0, str(ENGINE))

import pytest  # noqa: E402
import rebuttal as rb  # noqa: E402


def test_accept_when_checker_cannot_refute():
    loop = rb.RebuttalLoop(max_rounds=3)
    status = loop.add_round("SSRF reaches IMDS", refuted=False)
    assert status == rb.ACCEPTED
    assert loop.survives is True
    assert loop.verdict_hint() == "PASS"


def test_accept_after_one_failed_then_addressed():
    loop = rb.RebuttalLoop(max_rounds=3)
    assert loop.add_round("claim v1", refuted=True, reason="no internal response shown") == rb.OPEN
    assert loop.add_round("claim v2 with response body", refuted=False) == rb.ACCEPTED
    assert loop.survives is True


def test_exhausted_never_auto_accepts():
    loop = rb.RebuttalLoop(max_rounds=3)
    loop.add_round("v1", refuted=True, reason="reason A")
    loop.add_round("v2", refuted=True, reason="reason B")
    status = loop.add_round("v3", refuted=True, reason="reason C")
    assert status == rb.EXHAUSTED
    assert loop.survives is False           # critical: exhaustion is NOT acceptance
    assert loop.verdict_hint() == "DOWNGRADE"


def test_stall_on_repeated_refutation():
    loop = rb.RebuttalLoop(max_rounds=5, stall_repeats=2)
    assert loop.add_round("v1", refuted=True, reason="evidence does not show command output") == rb.OPEN
    status = loop.add_round("v2", refuted=True, reason="evidence does not show command output")
    assert status == rb.STALLED             # same refutation twice -> generator not addressing it
    assert loop.survives is False
    assert loop.verdict_hint() == "KILL"


def test_terminal_locks_the_verdict():
    loop = rb.RebuttalLoop()
    loop.add_round("claim", refuted=False)
    with pytest.raises(RuntimeError):
        loop.add_round("again", refuted=True, reason="x")


def test_default_skeptic_single_round_exhausts():
    # max_rounds=1 and the only round is refuted -> EXHAUSTED, not accepted
    loop = rb.RebuttalLoop(max_rounds=1)
    assert loop.add_round("v1", refuted=True, reason="weak") == rb.EXHAUSTED
    assert loop.survives is False


def test_state_is_auditable():
    loop = rb.RebuttalLoop(max_rounds=3)
    loop.add_round("v1", refuted=True, reason="needs proof")
    loop.add_round("v2", refuted=False)
    st = loop.state()
    assert st["status"] == rb.ACCEPTED
    assert st["rounds"] == 2
    assert st["survives"] is True
    assert st["history"][0]["reason"] == "needs proof"
    assert st["history"][1]["refuted"] is False


def test_refuted_without_reason_gets_default():
    loop = rb.RebuttalLoop(max_rounds=3)
    loop.add_round("v1", refuted=True)
    assert loop.rounds[0].reason == "unspecified"


# ===================== red-team regressions (raptor PR-2 wbfdsfq1r) =====================
def test_regression_distinct_blank_reasons_do_not_stall():
    # [6] two DISTINCT no-reason refutations must NOT collide on 'unspecified' -> mis-STALL/KILL.
    # They should fall through to EXHAUSTED -> DOWNGRADE (preserve the finding), not be killed.
    loop = rb.RebuttalLoop(max_rounds=5, stall_repeats=2)
    assert loop.add_round("addresses missing response", refuted=True) == rb.OPEN
    assert loop.add_round("a different, unaddressed issue", refuted=True) == rb.OPEN
    assert loop.status != rb.STALLED


def test_regression_blank_reasons_reach_exhausted_not_stalled():
    loop = rb.RebuttalLoop(max_rounds=2, stall_repeats=2)
    loop.add_round("v1", refuted=True)             # blank reason
    status = loop.add_round("v2", refuted=True)    # blank reason, hits max_rounds
    assert status == rb.EXHAUSTED                  # DOWNGRADE, not KILL
    assert loop.verdict_hint() == "DOWNGRADE"


def test_regression_real_repeated_reason_still_stalls():
    # the genuine stall case (identical NON-empty reason) must still trigger
    loop = rb.RebuttalLoop(max_rounds=5, stall_repeats=2)
    loop.add_round("v1", refuted=True, reason="evidence shows no command output")
    assert loop.add_round("v2", refuted=True, reason="evidence shows no command output") == rb.STALLED


def test_regression_non_string_reason_no_crash():
    # [7] a non-string reason must be coerced, not crash with AttributeError
    loop = rb.RebuttalLoop(max_rounds=3)
    loop.add_round("c", refuted=True, reason=5)     # must not raise
    assert loop.rounds[0].reason == "5"
