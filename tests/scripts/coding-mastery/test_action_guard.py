"""Tests for action_guard - 3-state decisions, circuit breaker, rate limiter (deterministic)."""
import json
import sys
from pathlib import Path

LIB = Path(__file__).resolve().parents[3] / "skills" / "coding-mastery" / "scripts" / "_lib"
sys.path.insert(0, str(LIB))

import action_guard as ag  # noqa: E402
import scope_guard as sg  # noqa: E402


def clock():
    box = {"t": 1000.0}
    return box, (lambda: box["t"])


# --------------------------------------------------------- method policy
def test_safe_method_allows():
    assert ag.ActionGuard().decide("GET", "acme.com").action == ag.ALLOW
    assert ag.ActionGuard().decide("HEAD", "acme.com").action == ag.ALLOW


def test_mutating_requires_approval():
    assert ag.ActionGuard().decide("POST", "acme.com").action == ag.REQUIRE_APPROVAL
    assert ag.ActionGuard().decide("DELETE", "acme.com").action == ag.REQUIRE_APPROVAL


def test_unknown_method_requires_approval():
    assert ag.ActionGuard().decide("FROBNICATE", "acme.com").action == ag.REQUIRE_APPROVAL


def test_allow_mutating_opt_in():
    assert ag.ActionGuard(allow_mutating=True).decide("POST", "acme.com").action == ag.ALLOW


def test_require_approval_all_downgrades_allow():
    assert ag.ActionGuard(require_approval_all=True).decide("GET", "acme.com").action == ag.REQUIRE_APPROVAL


# --------------------------------------------------------- scope integration
def test_out_of_scope_blocks():
    scope = sg.Scope({"engagement": "t", "in_scope": ["acme.com", "*.acme.com"]})
    g = ag.ActionGuard(scope)
    assert g.decide("GET", "evil.com").action == ag.BLOCK
    assert g.decide("GET", "api.acme.com").action == ag.ALLOW


def test_userinfo_target_blocked_by_scope():
    scope = sg.Scope({"engagement": "t", "in_scope": ["acme.com", "*.acme.com"]})
    # host resolves to evil.com -> out of scope -> block (same hardening as scope_guard)
    assert ag.ActionGuard(scope).decide("GET", "acme.com:80@evil.com").action == ag.BLOCK


# --------------------------------------------------------- circuit breaker
def test_circuit_breaker_opens_and_blocks():
    box, clk = clock()
    cb = ag.CircuitBreaker(threshold=3, cooldown=60, clock=clk)
    for _ in range(3):
        cb.record_failure("h")
    assert cb.is_open("h")
    assert ag.ActionGuard(breaker=cb).decide("GET", "h").action == ag.BLOCK


def test_circuit_breaker_half_open_after_cooldown():
    box, clk = clock()
    cb = ag.CircuitBreaker(threshold=2, cooldown=60, clock=clk)
    cb.record_failure("h"); cb.record_failure("h")
    assert cb.is_open("h")
    box["t"] += 61
    assert cb.is_open("h") is False           # cooldown elapsed -> retry allowed
    assert ag.ActionGuard(breaker=cb).decide("GET", "h").action == ag.ALLOW


def test_circuit_breaker_success_resets():
    box, clk = clock()
    cb = ag.CircuitBreaker(threshold=2, cooldown=60, clock=clk)
    cb.record_failure("h")
    cb.record_success("h")
    cb.record_failure("h")
    assert cb.is_open("h") is False           # success reset the counter


# --------------------------------------------------------- rate limiter
def test_rate_limiter():
    box, clk = clock()
    rl = ag.RateLimiter(rps=1, clock=clk)
    assert rl.allow("h") is True
    assert rl.allow("h") is False             # within 1s
    box["t"] += 1.0
    assert rl.allow("h") is True


def test_rate_limit_blocks_in_guard():
    box, clk = clock()
    rl = ag.RateLimiter(rps=1, clock=clk)
    g = ag.ActionGuard(limiter=rl)
    assert g.decide("GET", "h").action == ag.ALLOW
    assert g.decide("GET", "h").action == ag.BLOCK


# --------------------------------------------------------- state persistence (atomic, portable)
def test_state_round_trip(tmp_path):
    box, clk = clock()
    cb = ag.CircuitBreaker(threshold=2, cooldown=60, clock=clk)
    cb.record_failure("h"); cb.record_failure("h")
    path = str(tmp_path / "state.json")
    ag._save_state(path, cb)
    assert json.loads(Path(path).read_text())["breaker"]["opened_at"]

    cb2 = ag.CircuitBreaker(threshold=2, cooldown=60, clock=clk)
    ag._load_state(path, cb2)
    assert cb2.is_open("h")
    box["t"] += 61
    assert cb2.is_open("h") is False


def test_regression_poisoned_state_fails_closed(tmp_path):
    # one bad opened_at value must NOT silently drop the whole breaker (re-allowing a blocked host)
    box, clk = clock()
    cb = ag.CircuitBreaker(threshold=2, cooldown=60, clock=clk)
    cb.record_failure("acme.com"); cb.record_failure("acme.com")     # open
    path = str(tmp_path / "s.json")
    ag._save_state(path, cb)
    data = json.loads(Path(path).read_text())
    data["breaker"]["opened_at"]["b.com"] = "x"                       # poison a second host
    data["breaker"]["fails"]["b.com"] = 1
    Path(path).write_text(json.dumps(data))

    cb2 = ag.CircuitBreaker(threshold=2, cooldown=60, clock=clk)
    ag._load_state(path, cb2)
    assert cb2.is_open("acme.com") is True       # still blocked despite unrelated corruption
    assert cb2.is_open("b.com") is True          # unparseable opened_at -> treated as just-opened (fail-closed)
    assert ag.ActionGuard(breaker=cb2).decide("GET", "acme.com").action == ag.BLOCK


# --------------------------------------------------------- CLI exit codes
def test_cli_exit_codes(tmp_path):
    sf = tmp_path / "scope.json"
    sf.write_text('{"engagement":"t","in_scope":["*.acme.com"]}', encoding="utf-8")
    assert ag.main(["decide", "--method", "GET", "--target", "api.acme.com", "--scope", str(sf)]) == 0
    assert ag.main(["decide", "--method", "POST", "--target", "api.acme.com", "--scope", str(sf)]) == 4
    assert ag.main(["decide", "--method", "GET", "--target", "evil.com", "--scope", str(sf)]) == 5
    assert ag.main(["decide", "--method", "POST", "--target", "api.acme.com",
                    "--scope", str(sf), "--allow-mutating"]) == 0
    assert ag.main(["decide", "--method", "GET", "--target", "x", "--scope", str(tmp_path / "missing.json")]) == 2
