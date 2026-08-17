#!/usr/bin/env python3
"""agent_eval_selftest.py - frozen-baseline regression guard for the SCORED judge paths.

The plugin trusts two deterministic judge paths to gate expensive re-validation:
  * `engine/model_scorecard.py` - decides whether a (model, class) cell is TRUSTED (fail-closed).
  * `engine/rebuttal.py`        - decides ACCEPTED / STALLED / EXHAUSTED for the rebuttal loop.
plus one agent contract (`agents/finding-validator.md`) whose decision vocabulary those paths speak.

Unit tests prove each function in isolation; THIS is the calibration self-test: it runs the judge
paths against a small FROZEN set of golden scenarios with hand-verified expected verdicts, so a
subtle threshold/logic regression (e.g. a widened Wilson bound, a stall that no longer fires) is
caught as one CI signal. It is model-free and network-free: pure deterministic math + state.

BASELINE ISOLATION (load-bearing): the scorecard path writes to a sqlite DB. The self-test MUST use
a throwaway temp DB and NEVER read/write the operator's real `~/.claude/.../scorecard.sqlite`, or an
eval run would poison the very track record it is meant to check. Isolation is asserted in-code
(the temp path is verified != the real db_path()) before any record() call.

CLI:
  agent_eval_selftest.py --selftest      # run all golden scenarios; exit 1 on any regression
  agent_eval_selftest.py --selftest --json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "engine"))

import model_scorecard as ms  # noqa: E402
import rebuttal as rb  # noqa: E402


@dataclass
class Case:
    path: str          # which judge path
    name: str
    ok: bool
    detail: str = ""

    def to_dict(self) -> dict:
        return {"path": self.path, "name": self.name, "ok": self.ok, "detail": self.detail}


# --------------------------------------------------------------- model_scorecard
def _scorecard_cases(db: str) -> list[Case]:
    # Golden calibration table at DEFAULT thresholds (max_rate=0.05, min_n=20). Each row seeds a
    # fresh (model, class) cell in the ISOLATED db and asserts the trust verdict.
    cases: list[Case] = []

    def seed_and_check(cell: str, misses: int, n: int, expected: bool, why: str) -> Case:
        for i in range(n):
            ms.record("evalmodel", cell, overturned=(i < misses), path=db)
        trusted, _reason = ms.is_trusted("evalmodel", cell, path=db)
        return Case("model_scorecard", f"{cell}: {why}", trusted == expected,
                    "" if trusted == expected else f"expected trusted={expected}, got {trusted}")

    # empty cell -> never trusted (fail-closed on no data)
    t, _ = ms.is_trusted("evalmodel", "empty:cell", path=db)
    cases.append(Case("model_scorecard", "empty cell not trusted", t is False,
                      "" if t is False else "an unseen cell was trusted"))
    # clean but under min_n -> not trusted (wide interval)
    cases.append(seed_and_check("under_n:PASS", 0, 10, False, "clean n=10 < min_n not trusted"))
    # clean and large -> trusted
    cases.append(seed_and_check("clean_big:PASS", 0, 200, True, "clean n=200 trusted"))
    # a clean large cell tolerates a rare miss (Wilson upper still <=5%)...
    cases.append(seed_and_check("rare_miss:PASS", 1, 200, True, "1 miss in 200 still trusted"))
    # ...but enough misses push the Wilson upper bound past the threshold -> trust revoked (fail-closed)
    cases.append(seed_and_check("many_miss:PASS", 6, 200, False, "6 misses in 200 revokes trust"))
    # degenerate threshold rejected regardless of data (fail-closed)
    for i in range(200):
        ms.record("evalmodel", "degen:PASS", overturned=False, path=db)
    t, _ = ms.is_trusted("evalmodel", "degen:PASS", max_rate=float("nan"), path=db)
    cases.append(Case("model_scorecard", "NaN max_rate rejected", t is False,
                      "" if t is False else "a NaN threshold trusted a cell"))
    t, _ = ms.is_trusted("evalmodel", "degen:PASS", max_rate=1.5, path=db)
    cases.append(Case("model_scorecard", "max_rate>=1 rejected", t is False,
                      "" if t is False else "a >=1 threshold trusted a cell"))
    # wilson monotonicity: more misses never lowers the upper bound
    a = ms.wilson_upper(1, 100)
    b = ms.wilson_upper(5, 100)
    cases.append(Case("model_scorecard", "wilson upper monotone in misses", b >= a,
                      "" if b >= a else f"{b} < {a}"))
    return cases


# --------------------------------------------------------------- rebuttal loop
def _rebuttal_cases() -> list[Case]:
    cases: list[Case] = []

    # 1. checker cannot refute round 1 -> ACCEPTED / survives / PASS
    loop = rb.RebuttalLoop(max_rounds=3)
    loop.add_round("claimX", refuted=False)
    ok = loop.status == rb.ACCEPTED and loop.survives and loop.verdict_hint() == "PASS"
    cases.append(Case("rebuttal", "no-refute -> ACCEPTED/PASS", ok,
                      "" if ok else f"got {loop.status}/{loop.verdict_hint()}"))

    # 2. same reason repeated -> STALLED / KILL / not survives
    loop = rb.RebuttalLoop(max_rounds=5, stall_repeats=2)
    loop.add_round("claimX", refuted=True, reason="evidence is a 302 not an external host")
    loop.add_round("claimX", refuted=True, reason="evidence is a 302 not an external host")
    ok = loop.status == rb.STALLED and not loop.survives and loop.verdict_hint() == "KILL"
    cases.append(Case("rebuttal", "repeated reason -> STALLED/KILL", ok,
                      "" if ok else f"got {loop.status}/{loop.verdict_hint()}"))

    # 3. distinct refutations until max_rounds -> EXHAUSTED / DOWNGRADE (never auto-accept)
    loop = rb.RebuttalLoop(max_rounds=3, stall_repeats=2)
    loop.add_round("claimX", refuted=True, reason="reason A")
    loop.add_round("claimX", refuted=True, reason="reason B")
    loop.add_round("claimX", refuted=True, reason="reason C")
    ok = loop.status == rb.EXHAUSTED and not loop.survives and loop.verdict_hint() == "DOWNGRADE"
    cases.append(Case("rebuttal", "distinct refutes -> EXHAUSTED/DOWNGRADE", ok,
                      "" if ok else f"got {loop.status}/{loop.verdict_hint()}"))

    # 4. blank refutation reasons must NOT collide into a STALL (distinct refutations) -> EXHAUSTED
    loop = rb.RebuttalLoop(max_rounds=2, stall_repeats=2)
    loop.add_round("claimX", refuted=True, reason="")
    loop.add_round("claimX", refuted=True, reason="")
    ok = loop.status == rb.EXHAUSTED
    cases.append(Case("rebuttal", "blank reasons do not mis-STALL", ok,
                      "" if ok else f"got {loop.status}"))
    return cases


# --------------------------------------------------------------- finding-validator contract
def _validator_contract_cases(root: Path) -> list[Case]:
    f = root / "agents" / "finding-validator.md"
    try:
        text = f.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [Case("finding-validator", "agent file present", False, "agents/finding-validator.md unreadable")]
    cases = []
    for token in ("PASS", "KILL", "DOWNGRADE"):
        cases.append(Case("finding-validator", f"decision vocab {token!r} present", token in text,
                          "" if token in text else f"{token} missing from validator contract"))
    return cases


def run_selftest(root: Optional[Path] = None) -> list[Case]:
    root = Path(root) if root else _ROOT
    tmpdir = tempfile.mkdtemp(prefix="agent_eval_")
    db = os.path.join(tmpdir, "scorecard.sqlite")
    # BASELINE ISOLATION assertion: never touch the operator's real scorecard DB.
    if os.path.abspath(db) == os.path.abspath(ms.db_path()):
        return [Case("isolation", "temp DB distinct from real scorecard", False,
                     "self-test DB path collided with the real scorecard DB - refusing to run")]
    cases: list[Case] = [Case("isolation", "temp DB distinct from real scorecard", True)]
    cases += _scorecard_cases(db)
    cases += _rebuttal_cases()
    cases += _validator_contract_cases(root)
    return cases


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Frozen-baseline self-test for the scored judge paths.")
    p.add_argument("--selftest", action="store_true", help="run all golden scenarios")
    p.add_argument("--json", action="store_true")
    p.add_argument("--root")
    args = p.parse_args(argv)
    if not args.selftest:
        p.error("nothing to do; pass --selftest")
    try:
        cases = run_selftest(Path(args.root) if args.root else None)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    failed = [c for c in cases if not c.ok]
    if args.json:
        print(json.dumps([c.to_dict() for c in cases], indent=2))
    else:
        for c in cases:
            mark = "ok  " if c.ok else "FAIL"
            line = f"  [{mark}] {c.path}: {c.name}"
            if not c.ok and c.detail:
                line += f"  <- {c.detail}"
            print(line)
        print(f"{'ok' if not failed else 'FAILED'}: {len(cases) - len(failed)}/{len(cases)} golden scenarios passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
