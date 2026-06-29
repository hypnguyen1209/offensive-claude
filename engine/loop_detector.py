#!/usr/bin/env python3
"""loop_detector.py - detect when the engine is stuck repeating the same action.

A sliding window of recent action signatures. When a signature recurs `max_repeats` times
within the window, the engine is looping (a rabbit hole) and should pivot/skip rather than
keep hammering the same move. Pure + deterministic.
"""
from __future__ import annotations

from collections import deque, Counter


class LoopDetector:
    def __init__(self, window: int = 12, max_repeats: int = 5, max_total: int = 8):
        self.window = max(1, int(window))
        self.max_repeats = max(2, int(max_repeats))
        self.max_total = max(self.max_repeats, int(max_total))
        self._recent: deque = deque(maxlen=self.window)
        self._total: Counter = Counter()

    def observe(self, signature: str) -> bool:
        """Record a signature; return True if it is looping. Catches BOTH a tight burst
        (>= max_repeats within the sliding window) AND sustained recurrence across the whole
        run (>= max_total total observations) — so an alternating A,B,A,B loop is caught too."""
        self._recent.append(signature)
        self._total[signature] += 1
        return self._recent.count(signature) >= self.max_repeats or self._total[signature] >= self.max_total

    def count(self, signature: str) -> int:
        return self._recent.count(signature)

    def reset(self) -> None:
        self._recent.clear()
        self._total.clear()
