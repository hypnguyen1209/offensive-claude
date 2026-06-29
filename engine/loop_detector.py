#!/usr/bin/env python3
"""loop_detector.py - detect when the engine is stuck repeating the same action.

A sliding window of recent action signatures. When a signature recurs `max_repeats` times
within the window, the engine is looping (a rabbit hole) and should pivot/skip rather than
keep hammering the same move. Pure + deterministic.
"""
from __future__ import annotations

from collections import deque


class LoopDetector:
    def __init__(self, window: int = 12, max_repeats: int = 5):
        self.window = max(1, int(window))
        self.max_repeats = max(2, int(max_repeats))
        self._recent: deque = deque(maxlen=self.window)

    def observe(self, signature: str) -> bool:
        """Record a signature; return True if it has now recurred >= max_repeats in the window."""
        self._recent.append(signature)
        return self._recent.count(signature) >= self.max_repeats

    def count(self, signature: str) -> int:
        return self._recent.count(signature)

    def reset(self) -> None:
        self._recent.clear()
