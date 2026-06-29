#!/usr/bin/env python3
"""tracer.py - append-only JSONL run trace + resume support.

Every engine decision/action is recorded as one JSONL event (auditable, and the basis for
--resume: completed step ids are read back so a re-run skips finished work). Append-only, so a
crash mid-run leaves a usable partial trace.
"""
from __future__ import annotations

import json
import os
from typing import Callable, Optional


class Tracer:
    def __init__(self, path: str, clock: Optional[Callable[[], float]] = None):
        self.path = path
        self._clock = clock
        self._seq = self._last_seq()

    def _last_seq(self) -> int:
        n = 0
        for ev in self.events():
            n = max(n, int(ev.get("seq", 0)))
        return n

    def record(self, event_type: str, **fields) -> dict:
        self._seq += 1
        ev = {"seq": self._seq, "type": event_type}
        if self._clock is not None:
            ev["ts"] = self._clock()
        ev.update(fields)
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(ev) + "\n")
        return ev

    def events(self) -> list:
        out = []
        if not os.path.isfile(self.path):
            return out
        with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
        return out

    def completed_step_ids(self) -> set:
        """Step ids that reached a 'step_done' event (used by --resume)."""
        return {ev["step_id"] for ev in self.events()
                if ev.get("type") == "step_done" and "step_id" in ev}
