#!/usr/bin/env python3
"""engine.py - bounded, resumable, traceable engagement runner.

NOT an LLM brain (no LangGraph/Ollama). A deterministic scaffold that sequences a workflow's
kill-chain phases under HARD discipline: a step/time budget, loop detection (no rabbit holes),
an append-only JSONL trace, operator `bump.txt` injection, and --resume. It runs only
registered, SAFE actions (scope checks, memory recall, phase/notes); offensive technique
execution stays with the operator/skills and is gated by action_guard - the engine enforces
the control loop, it does not free-hack.

CLI:
  engine.py run --workflow web-app-pentest [--target acme.com] [--scope scope.json]
                [--max-steps N] [--max-seconds S] [--state .engage/engine] [--resume]
  exit 0 ok, 3 halted on scope violation, 2 error
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from typing import Callable, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, os.path.join(_ROOT, "skills", "coding-mastery", "scripts", "_lib"))
sys.path.insert(0, os.path.join(_ROOT, "skills", "engagement-memory", "scripts"))

from budget import Budget          # noqa: E402
from loop_detector import LoopDetector  # noqa: E402
from tracer import Tracer          # noqa: E402

# --------------------------------------------------------------------------- actions
ACTIONS: dict = {}


def action(name: str) -> Callable:
    def deco(fn):
        ACTIONS[name] = fn
        return fn
    return deco


@action("phase")
def _phase(ctx: dict, step: dict) -> dict:
    # records the phase entry + its guidance; the operator/skills do the judgment work
    return {"phase": step.get("phase"), "skills": step.get("skills", []),
            "gate": (step.get("gate") or {}).get("required", [])}


@action("scope_check")
def _scope_check(ctx: dict, step: dict) -> dict:
    scope = ctx.get("scope")
    target = step.get("target") or ctx.get("target")
    if not scope or not target:
        return {"target": target, "skipped": "no scope or target"}
    d = scope.evaluate(target)
    return {"target": target, "in_scope": d.in_scope, "reason": d.reason}


@action("recall")
def _recall(ctx: dict, step: dict) -> dict:
    try:
        import pattern_db
        recs = pattern_db.merged(pattern_db.default_db())
        hits = pattern_db.match(recs, vuln_class=step.get("vuln_class"),
                                tech_stack=step.get("tech_stack"), target=ctx.get("target"), top=step.get("top", 5))
        return {"recalled": len(hits), "top": [{"vuln_class": h["vuln_class"], "technique": h.get("technique"),
                                                "cvss": h.get("cvss")} for h in hits[:5]]}
    except Exception as exc:  # memory is best-effort
        return {"recalled": 0, "note": f"recall unavailable: {exc}"}


@action("note")
def _note(ctx: dict, step: dict) -> dict:
    return {"note": step.get("text", "")}


def _unknown(ctx: dict, step: dict) -> dict:
    return {"unknown_action": step.get("action")}


# --------------------------------------------------------------------------- workflow loader
def load_workflow(name_or_path: str) -> dict:
    import yaml  # lazy: engine core + tests don't require pyyaml
    path = name_or_path
    if not os.path.isfile(path):
        cand = os.path.join(_ROOT, "workflows", f"{name_or_path}.yml")
        if os.path.isfile(cand):
            path = cand
        else:
            raise FileNotFoundError(f"workflow not found: {name_or_path}")
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def plan_from_workflow(wf: dict, target: Optional[str] = None) -> list:
    """Ordered phase steps, following each phase's `next`. Inserts a scope_check + recall
    around the early phases so the run starts safe and informed."""
    phases = (wf or {}).get("phases", {})
    if not phases:
        return []
    order, seen = [], set()
    cur = "scope" if "scope" in phases else next(iter(phases))
    while cur and cur in phases and cur not in seen:
        seen.add(cur)
        order.append(cur)
        cur = phases[cur].get("next")
    plan = []
    for name in order:
        ph = phases[name]
        if name == "scope" and target:
            # always=True -> the scope gate is NEVER skipped by --resume (a forged trace can't bypass it)
            plan.append({"id": "scope_check", "action": "scope_check", "phase": name, "target": target, "always": True})
        plan.append({"id": f"phase:{name}", "action": "phase", "phase": name,
                     "skills": ph.get("skills", []), "templates": ph.get("templates", []),
                     "gate": ph.get("gate", {})})
        if name in ("recon", "weaponize"):
            plan.append({"id": f"recall:{name}", "action": "recall", "phase": name})
    return plan


# --------------------------------------------------------------------------- engine
class Engine:
    def __init__(self, plan: list, *, tracer: Tracer, budget: Budget,
                 loop_detector: Optional[LoopDetector] = None, scope=None,
                 target: Optional[str] = None, bump_path: Optional[str] = None):
        self.plan = plan
        self.tracer = tracer
        self.budget = budget
        self.loops = loop_detector or LoopDetector()
        self.ctx = {"scope": scope, "target": target}
        self.bump_path = bump_path

    def _consume_bump(self) -> None:
        if not self.bump_path or not os.path.isfile(self.bump_path):
            return
        text = open(self.bump_path, "r", encoding="utf-8", errors="replace").read().strip()
        if text:
            self.tracer.record("operator_bump", text=text)
            open(self.bump_path, "w", encoding="utf-8").close()  # consume

    def _plan_hash(self) -> str:
        payload = json.dumps([[s.get("id"), s.get("action")] for s in self.plan], sort_keys=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def run(self, resume: bool = False) -> dict:
        plan_hash = self._plan_hash()
        completed = self.tracer.completed_step_ids(plan_hash) if resume else set()
        self.tracer.record("run_started", plan_len=len(self.plan), resume=resume,
                           completed=len(completed), plan_hash=plan_hash)
        halted = None
        for step in self.plan:
            sid = step.get("id", step.get("action", "?"))
            # safety-critical steps (always=True, e.g. scope_check) are NEVER skipped by resume
            if sid in completed and not step.get("always"):
                self.tracer.record("step_skipped_resume", step_id=sid)
                continue
            ex, why = self.budget.exhausted()
            if ex:
                halted = why
                self.tracer.record("halted", reason=why, can_finish=self.budget.can_finish())
                break
            self._consume_bump()
            sig = f"{step.get('action')}:{step.get('target', '')}:{step.get('phase', '')}"
            if self.loops.observe(sig):
                self.tracer.record("loop_detected", step_id=sid, signature=sig, action="pivot/skip")
                continue
            try:
                result = ACTIONS.get(step.get("action"), _unknown)(self.ctx, step)
            except Exception as exc:  # one bad step must not crash the whole run
                self.tracer.record("step_error", step_id=sid, error=str(exc))
                self.budget.tick()
                continue
            self.budget.tick()
            self.tracer.record("step_done", step_id=sid, action=step.get("action"),
                               phase=step.get("phase"), result=result)
            # the scope gate is non-negotiable: an out-of-scope target halts the whole run
            if step.get("action") == "scope_check" and result.get("in_scope") is False:
                halted = f"scope violation: {result.get('target')} is out of scope"
                self.tracer.record("scope_violation", step_id=sid, target=result.get("target"),
                                   reason=result.get("reason"))
                break
        finished = halted is None and self.budget.can_finish()
        self.tracer.record("run_finished", steps=self.budget.steps,
                           elapsed=round(self.budget.elapsed(), 3), halted=halted, finished=finished)
        return {"steps": self.budget.steps, "halted": halted, "finished": finished}


# --------------------------------------------------------------------------- CLI
def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(description="Bounded, resumable engagement engine.")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--workflow", required=True)
    r.add_argument("--target")
    r.add_argument("--scope")
    r.add_argument("--state", default=".engage/engine")
    r.add_argument("--max-steps", type=int, default=50)
    r.add_argument("--max-seconds", type=float, default=7200.0)
    r.add_argument("--min-steps", type=int, default=3)
    r.add_argument("--resume", action="store_true")

    args = p.parse_args(argv)
    try:
        wf = load_workflow(args.workflow)
        plan = plan_from_workflow(wf, target=args.target)
        scope = None
        if args.scope:
            import scope_guard
            scope = scope_guard.Scope.load(args.scope)
        os.makedirs(args.state, exist_ok=True)
        tracer = Tracer(os.path.join(args.state, "trace.jsonl"))
        budget = Budget(max_steps=args.max_steps, max_seconds=args.max_seconds, min_steps=args.min_steps)
        eng = Engine(plan, tracer=tracer, budget=budget, scope=scope, target=args.target,
                     bump_path=os.path.join(args.state, "bump.txt"))
        summary = eng.run(resume=args.resume)
        print(f"engine: {summary['steps']} steps, finished={summary['finished']}, "
              f"halted={summary['halted']}; trace={tracer.path}")
        if summary["halted"] and "scope violation" in summary["halted"]:
            return 3   # halted on a scope violation — automation must notice
        return 0
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
