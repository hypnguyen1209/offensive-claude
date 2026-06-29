#!/usr/bin/env python3
"""action_guard.py - runtime gate for outward actions during an engagement.

A 3-state decision (allow | require_approval | block) for "should this request go out?",
combining four controls so automation and operators can't quietly do something the ROE
forbids or hammer a host into the ground:

  1. SCOPE      - out-of-scope target -> block (delegates to scope_guard.py).
  2. SAFE METHOD- read-only verbs (GET/HEAD/OPTIONS) auto-allow; mutating verbs
                  (POST/PUT/PATCH/DELETE/...) -> require_approval unless ROE allows them.
  3. CIRCUIT    - per-host breaker: N consecutive failures -> block the host for a cooldown
                  (stop pounding a broken/blocking target; classic blue-team tripwire too).
  4. RATE LIMIT - optional per-host min-interval pacing.

Design notes vs the framework we borrowed the idea from:
- No confusing "disabled = paranoid" inversion. Explicit flags: `require_approval_all`
  (downgrade every allow to require_approval) and `allow_mutating` (ROE opt-in).
- Portable: optional state persistence uses an atomic os.replace temp-write, NOT fcntl.
- Deterministic: time source is injectable (`clock=`), so tests don't sleep.

CLI:
  action_guard.py decide --method POST --target https://api.acme.com/x [--scope scope.json]
                          [--allow-mutating] [--require-approval-all] [--state state.json]
  exit 0 = allow, 4 = require_approval, 5 = block, 2 = error
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, asdict, field
from typing import Callable, Optional

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
KNOWN_METHODS = SAFE_METHODS | frozenset({"POST", "PUT", "PATCH", "DELETE", "CONNECT", "TRACE"})

ALLOW, REQUIRE_APPROVAL, BLOCK = "allow", "require_approval", "block"
_EXIT = {ALLOW: 0, REQUIRE_APPROVAL: 4, BLOCK: 5}


@dataclass
class Decision:
    action: str          # allow | require_approval | block
    reason: str
    host: str = ""
    method: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class CircuitBreaker:
    """Per-host breaker. `threshold` consecutive failures opens it for `cooldown` seconds."""

    def __init__(self, threshold: int = 5, cooldown: float = 60.0, clock: Callable[[], float] = time.monotonic):
        self.threshold = max(1, int(threshold))
        self.cooldown = float(cooldown)
        self.clock = clock
        self._fails: dict[str, int] = {}
        self._opened_at: dict[str, float] = {}

    def is_open(self, host: str) -> bool:
        opened = self._opened_at.get(host)
        if opened is None:
            return False
        if self.clock() - opened >= self.cooldown:
            # cooldown elapsed -> half-open: clear and allow a retry
            self._opened_at.pop(host, None)
            self._fails[host] = 0
            return False
        return True

    def record_failure(self, host: str) -> None:
        self._fails[host] = self._fails.get(host, 0) + 1
        if self._fails[host] >= self.threshold:
            self._opened_at[host] = self.clock()

    def record_success(self, host: str) -> None:
        self._fails[host] = 0
        self._opened_at.pop(host, None)

    def load(self, data: dict) -> None:
        # fail CLOSED + resilient: drop only bad entries, and treat an unparseable
        # opened_at as "just opened" so a recorded-open host stays BLOCKED.
        fails = {}
        for k, v in (data.get("fails") or {}).items():
            try:
                fails[k] = int(v)
            except (TypeError, ValueError):
                fails[k] = self.threshold
        opened = {}
        for k, v in (data.get("opened_at") or {}).items():
            try:
                opened[k] = float(v)
            except (TypeError, ValueError):
                opened[k] = self.clock()
        self._fails = fails
        self._opened_at = opened

    def dump(self) -> dict:
        return {"fails": self._fails, "opened_at": self._opened_at}


class RateLimiter:
    """Optional per-host minimum interval (seconds). rps<=0/None disables it."""

    def __init__(self, rps: Optional[float] = None, clock: Callable[[], float] = time.monotonic):
        self.min_interval = (1.0 / rps) if rps and rps > 0 else 0.0
        self.clock = clock
        self._last: dict[str, float] = {}

    def allow(self, host: str) -> bool:
        if self.min_interval <= 0:
            return True
        now = self.clock()
        last = self._last.get(host)
        if last is not None and (now - last) < self.min_interval:
            return False
        self._last[host] = now
        return True


def classify_method(method: str, allow_mutating: bool = False) -> str:
    m = (method or "GET").upper()
    if m in SAFE_METHODS:
        return ALLOW
    if allow_mutating:
        return ALLOW
    return REQUIRE_APPROVAL  # mutating or unknown verb -> human in the loop


class ActionGuard:
    def __init__(self, scope=None, *, allow_mutating: bool = False, require_approval_all: bool = False,
                 breaker: Optional[CircuitBreaker] = None, limiter: Optional[RateLimiter] = None):
        self.scope = scope
        self.allow_mutating = allow_mutating
        self.require_approval_all = require_approval_all
        self.breaker = breaker or CircuitBreaker()
        self.limiter = limiter or RateLimiter()

    def _host(self, target: str) -> str:
        try:
            import scope_guard
            return scope_guard.split_host_port(target)[0]
        except Exception:
            return target

    def decide(self, method: str, target: str) -> Decision:
        host = self._host(target)
        # 1. scope (out-of-scope is non-negotiable)
        if self.scope is not None:
            d = self.scope.evaluate(target)
            if not d.in_scope:
                return Decision(BLOCK, f"out-of-scope: {d.reason}", host, method)
        # 2. circuit breaker
        if self.breaker.is_open(host):
            return Decision(BLOCK, f"circuit breaker open for {host} (too many failures)", host, method)
        # 3. rate limit
        if not self.limiter.allow(host):
            return Decision(BLOCK, f"rate limit exceeded for {host}", host, method)
        # 4. method policy
        action = classify_method(method, self.allow_mutating)
        reason = "read-only method" if action == ALLOW else f"mutating/unknown method {method.upper()} needs approval"
        # 5. global gate
        if self.require_approval_all and action == ALLOW:
            action, reason = REQUIRE_APPROVAL, "require_approval_all is set"
        return Decision(action, reason, host, method)


def _load_state(path: Optional[str], breaker: CircuitBreaker) -> None:
    if path and os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                breaker.load(json.load(fh).get("breaker", {}))
        except (OSError, ValueError):
            pass


def _save_state(path: Optional[str], breaker: CircuitBreaker) -> None:
    if not path:
        return
    tmp = f"{path}.tmp{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"breaker": breaker.dump()}, fh)
    os.replace(tmp, path)  # atomic, portable (no fcntl)


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Runtime action guard (3-state).")
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("decide", help="decide whether an action may proceed")
    d.add_argument("--method", default="GET")
    d.add_argument("--target", required=True)
    d.add_argument("--scope", help="scope.json (enables scope enforcement)")
    d.add_argument("--allow-mutating", action="store_true", help="ROE permits mutating methods")
    d.add_argument("--require-approval-all", action="store_true")
    d.add_argument("--state", help="circuit-breaker state file (persisted atomically)")
    d.add_argument("--json", action="store_true")

    args = p.parse_args(argv)
    try:
        scope = None
        if args.scope:
            import scope_guard
            scope = scope_guard.Scope.load(args.scope)
        # wall-clock so persisted opened_at is comparable across CLI invocations
        breaker = CircuitBreaker(clock=time.time)
        _load_state(args.state, breaker)
        guard = ActionGuard(scope, allow_mutating=args.allow_mutating,
                            require_approval_all=args.require_approval_all, breaker=breaker)
        dec = guard.decide(args.method, args.target)
        _save_state(args.state, breaker)
        if args.json:
            print(json.dumps(dec.to_dict()))
        else:
            print(f"{dec.action.upper()}: {dec.method.upper()} {dec.target if False else args.target} "
                  f"-> {dec.host} - {dec.reason}")
        return _EXIT[dec.action]
    except Exception as exc:  # never fail OPEN
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
