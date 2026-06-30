#!/usr/bin/env python3
"""rebuttal.py - bounded generator<->checker rebuttal loop as STRUCTURED state.

The pattern (from raptor's hypothesis<->checker cycle, minus its brittle filename-polling): a
generator asserts a finding, an independent checker (see agents/finding-checker.md) tries to
refute it. If the checker can't refute, the finding is ACCEPTED. If they keep refuting, the loop
must NOT run forever and must NOT auto-accept on exhaustion - default-to-skeptic.

This module is the deterministic state holder, NOT an LLM brain (consistent with engine.py): the
operator/harness runs the actual generator and checker, and feeds each round's outcome in here.
It decides convergence and keeps an auditable history. It composes LoopDetector to notice a STALL
(the checker repeating the same refutation - the generator isn't addressing it).

Terminal states:
  ACCEPTED   - a round where the checker did NOT refute. The finding survives.
  STALLED    - the same refutation recurred `stall_repeats` times. Generator isn't fixing it -> drop/downgrade.
  EXHAUSTED  - hit `max_rounds` with no acceptance. Unresolved -> DOWNGRADE (never silently accept).
Only ACCEPTED means the finding survives; STALLED/EXHAUSTED do not.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from loop_detector import LoopDetector  # noqa: E402

OPEN = "OPEN"
ACCEPTED = "ACCEPTED"
STALLED = "STALLED"
EXHAUSTED = "EXHAUSTED"
_TERMINAL = {ACCEPTED, STALLED, EXHAUSTED}


@dataclass
class Round:
    n: int
    claim: str
    refuted: bool
    reason: str = ""

    def to_dict(self) -> dict:
        return {"n": self.n, "claim": self.claim, "refuted": self.refuted, "reason": self.reason}


class RebuttalLoop:
    def __init__(self, max_rounds: int = 3, stall_repeats: int = 2):
        self.max_rounds = max(1, int(max_rounds))
        self.stall_repeats = max(2, int(stall_repeats))
        self.status = OPEN
        self.rounds: list = []
        # detect the same refutation reason recurring -> a stalled (non-converging) rebuttal
        self._stall = LoopDetector(window=max(64, self.max_rounds * 4),
                                   max_repeats=self.stall_repeats, max_total=self.stall_repeats)

    @property
    def is_terminal(self) -> bool:
        return self.status in _TERMINAL

    @property
    def survives(self) -> bool:
        """The finding survives the rebuttal ONLY if the checker accepted it."""
        return self.status == ACCEPTED

    def add_round(self, claim: str, refuted: bool, reason: str = "") -> str:
        """Record one generator->checker round; return the resulting status.

        After a terminal status, further rounds are refused (the verdict is locked)."""
        if self.is_terminal:
            raise RuntimeError(f"rebuttal already terminal ({self.status}); cannot add a round")
        n = len(self.rounds) + 1
        # coerce any caller type to a string (operator/harness-supplied); never crash on add_round
        real_reason = ("" if reason is None else str(reason)).strip()
        stored = real_reason or ("unspecified" if refuted else "")
        self.rounds.append(Round(n, str(claim), bool(refuted), stored))

        if not refuted:
            self.status = ACCEPTED          # checker couldn't refute -> survives
            return self.status
        # STALL only on a genuinely-identical, NON-EMPTY refutation reason. A blank/unspecified
        # reason must NOT collide with another blank one (that would mis-KILL distinct refutations);
        # such non-converging loops fall through to EXHAUSTED -> DOWNGRADE instead.
        if real_reason and self._stall.observe(real_reason):
            self.status = STALLED
            return self.status
        if n >= self.max_rounds:
            self.status = EXHAUSTED         # ran out of rounds, still refuted -> unresolved
            return self.status
        self.status = OPEN
        return self.status

    def verdict_hint(self) -> str:
        """Map the loop outcome to a finding-pipeline action (advisory)."""
        return {ACCEPTED: "PASS", STALLED: "KILL", EXHAUSTED: "DOWNGRADE",
                OPEN: "CONTINUE"}[self.status]

    def state(self) -> dict:
        return {"status": self.status, "survives": self.survives, "rounds": len(self.rounds),
                "max_rounds": self.max_rounds, "verdict_hint": self.verdict_hint(),
                "history": [r.to_dict() for r in self.rounds]}
