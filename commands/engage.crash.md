---
description: Crash → root cause → reachability → empirical exploitability verdict (native bugs)
---

# /engage.crash

Takes a crash (or a fuzzing corpus) for a **native** target and produces a validated root cause plus a
machine-checkable exploitability verdict — the crash→exploitability pipeline (raptor-adoption PR-3). It
sequences the rr/coverage/feasibility skills under the engagement's scope and action gates. Runs in the
binary-analysis devcontainer (`.devcontainer/`); the rr/gcov/compile steps need a Linux toolchain and
**degrade gracefully** (skip with a notice) where a tool is absent.

## Usage

`/engage.crash --target <binary> [--input <poc>] [--source <dir>] [--build "<gcc {cflags} cmd>"]`

## Process

### 1. Scope + safety (always first)
- `scope_guard.py check <target>` — reproduction/exec only inside authorization.
- Reproduction and witness replay are analysis, but any *exec* is routed through `action_guard.py`;
  this command never auto-runs an exploit PoC (that stays behind the gate).

### 2. Reproduce + root cause (rr time-travel)
- `skills/reverse-engineering/scripts/rr_root_cause.sh <target> @@` (CRASH_INPUT=<poc>) — deterministic
  record/replay; reverse-step to the corrupting write. See `skills/reverse-engineering/references/rr-time-travel.md`.
- Output: a **`trace_proof`** artifact (function trace) + a root-cause summary.

### 3. Prove reachability (coverage)
- If source is available, build `--coverage`, run the witness, `gcov` the vulnerable line — see
  `skills/reverse-engineering/references/coverage-reachability.md`. Output: a **`coverage_proof`** (gcov line-hit).
- Either artifact satisfies the native-bug reachability bar in `validate_findings.py`.

### 4. Empirical feasibility (mitigation matrix)
- `exploit_context.py build --target <binary>` — cache checksec/libc/arch once.
- `feasibility_profile.py run --build "<gcc {cflags} ...>" --witness "<./w poc>" --context exploit-context.json`
  — rebuild the witness under permissive/distro/hardened/asan, record which still fire, derive the
  blocked-technique map. See `skills/exploit-development/references/exploit-feasibility.md`.

### 5. Record the finding (gated)
- Write the finding with `proof.coverage_proof`/`proof.trace_proof`, and demonstrated-vs-inherent
  severity + a `feasibility` verdict (`true`/`false`/`null`; a tool limit is `null`, never `false`).
- Run `validate_findings.py --findings f.json --evidence ./evidence --evidence-store evidence.json
  --strict` then the `finding-validator` agent. A native bug without a reachability artifact stays
  `[POSSIBLE]`. `/exploit` must not use any technique `exploit_context.py check` reports BLOCKED.

### 6. Persist + next
- Store the confirmed root-cause pattern in engagement-memory (`pattern_db.py record`).
- Results land in the autopilot trace/resume (`engine/`). Next: `/engage.exploit` (within the
  empirically-allowed technique set) or `/engage.report`.

## Gate Check
- Root-cause artifact present (rr trace or gcov line-hit).
- Native finding carries a reachability proof → tiers `[CONFIRMED]` only then.
- `exploit-context.json` written; the report cites the empirical mitigation map and feasibility verdict.

## Available Skills
- `04-reverse-engineering` — rr time-travel, coverage, decompilation
- `02-vulnerability-analysis` — `validate_findings.py`, `path_conditions.py`, `variant_hunt.py`
- `03-exploit-development` — `exploit_context.py`, `feasibility_profile.py`, weaponization

## Notes
This is the most defensible part of the pipeline: rebuilding the crash witness under real mitigation
profiles is artefact-grade, far stronger than static "checksec says X". Keep rr traces (they may hold
secrets) in the scoped workspace and purge on teardown.
