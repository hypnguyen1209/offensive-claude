#!/usr/bin/env python3
"""budget.py - hard step/time budget for the engagement engine.

Stops a runaway/rabbit-hole loop: a bounded number of steps, a wall-clock ceiling, and a
minimum number of steps before the engine is allowed to declare itself finished (so it can't
bail on step 1). Time source is injectable for deterministic tests.
"""
from __future__ import annotations

import time
from typing import Callable, Optional


class Budget:
    def __init__(self, max_steps: int = 50, max_seconds: float = 7200.0,
                 min_steps: int = 3, clock: Callable[[], float] = time.monotonic):
        self.max_steps = max(1, int(max_steps))
        self.max_seconds = float(max_seconds)
        self.min_steps = max(1, int(min_steps))   # floor 1: a 'finished' run did >=1 real step
        self.clock = clock
        self.steps = 0
        self._t0 = clock()

    def tick(self, n: int = 1) -> None:
        self.steps += n

    def elapsed(self) -> float:
        return self.clock() - self._t0

    def exhausted(self) -> tuple:
        """(bool, reason). True when no further steps may run."""
        if self.steps >= self.max_steps:
            return True, f"step budget reached ({self.steps}/{self.max_steps})"
        if self.elapsed() >= self.max_seconds:
            return True, f"time budget reached ({self.elapsed():.0f}s/{self.max_seconds:.0f}s)"
        return False, ""

    def can_finish(self) -> bool:
        """The engine may only declare 'finished' after the minimum useful work."""
        return self.steps >= self.min_steps

    def remaining_steps(self) -> int:
        return max(0, self.max_steps - self.steps)
