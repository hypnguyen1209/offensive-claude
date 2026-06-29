---
description: Resume an engagement from the engine trace — skip completed steps, continue where you left off
---

# /engage.pickup

Resume an in-progress engagement. The autopilot engine writes an append-only trace
(`<state>/trace.jsonl`); pickup re-runs the workflow with `--resume`, so completed steps are
skipped and the run continues from the first unfinished step.

## Usage

`/engage.pickup [--workflow <name>] [--state .engage/engine]`

## Process

### 1. Locate prior run
Read `<state>/trace.jsonl`. Summarize: which phases/steps completed (`step_done`), whether the
prior run `halted` (budget/loop) or `finished`, and any `operator_bump` directives recorded.

### 2. Resume
```bash
python engine/engine.py run --workflow <name> --target <host> \
    --scope .engage/scope/scope.json --state .engage/engine --resume
```
Completed `step_id`s are skipped (`step_skipped_resume`); the budget restarts for the new run, so
raise `--max-steps`/`--max-seconds` if the prior run halted on budget.

### 3. Re-orient
Before continuing manual work, reload context:
- `.engage/scope/scope.json` — the enforced boundary
- `.engage/recon/prior-intel.*` — recalled patterns (run `/engage.memory recall` if stale)
- `exploit/findings/` — findings already recorded
- the trace's last `step_done` — where execution stopped

### 4. Operator bump (optional)
Drop a directive into `<state>/bump.txt` (e.g. "also test the staging host") before resuming; the
engine records and consumes it between steps.

## Notes

- The trace is the resumable state — keep `<state>/` with the engagement artifacts.
- A `halted` prior run is normal (it means the budget/loop guard fired) — review the reason, adjust
  budget or pivot, then pick up.
