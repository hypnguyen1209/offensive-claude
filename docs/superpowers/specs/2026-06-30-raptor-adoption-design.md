# Design Spec — raptor adoption (learning from gadievron/raptor)

**Date:** 2026-06-30
**Branch:** `feat/raptor-adoption`
**Status:** PR-1 done (merged to main). PR-2 done (on `feat/raptor-adoption`). PR-3 pending.

## Goal

Adopt the genuinely-new *content* from `github.com/gadievron/raptor` — a crash→exploitability
staged-proof pipeline + OSS-repo forensics — into offensive-claude **without** copying its
heavyweight scaffolding (Pydantic/BigQuery stack, 8-stage lettered state machine, filename-polling,
`--privileged` containers, `/raptor-*` aliasing). Everything lands on our existing thin-router +
`references/` + `scripts/` model, stays stdlib-only, ships behind existing gates, and keeps the
`scope_guard` authorization boundary intact.

## What raptor adds that we lack (net-new), vs. what we already do better

**Net-new (worth adopting):** staged crash→exploitability proof (rr / gcov line-hit / function-trace
reachability); empirical mitigation-matrix (rebuild the crash witness under N CFLAGS profiles, record
which still fire); a separate adversarial *checker* agent that sees only the artifact; typed
re-verifiable evidence (`EVD-XXX` + `source_url` + `content_sha256` + `verify_all()`); OSS supply-chain
forensics (dangling commits, GH-Archive, Wayback, live API); SMT path-condition tri-state;
variant-hunt-from-seed; untrusted-repo subprocess hardening.

**Already stronger (do not regress):** `validate_findings.py` boolean-driven tiers; the
PASS/KILL/DOWNGRADE `finding-validator`; mandatory CWE/CVSS/ATT&CK templated records; bounded
autopilot (`engine/`); `engagement-memory`; `scope_guard`/`action_guard`; angr/Triton/Z3 worked
examples; 224 tests + CI.

## Correction to the workflow analysis

The analysis assumed `finding-evidence-standards.md` and `finding-validation-runtime.md` did **not**
exist. They **do** (`skills/references/`, created 2026-06-29) and are mature. PR-1 therefore
**extends** them rather than creating them.

## PR plan

### PR-1 — Discipline + hardening (this PR, no Linux toolchain, all stdlib)

Pure-additive. One new code file (tested); the rest are documentation extensions.

1. **`skills/coding-mastery/scripts/_lib/safe_subprocess.py`** (NEW, + tests). Mirrors
   `scope_guard.py` house style: pure stdlib, fail-closed, `main(argv)` exit codes, dataclass result.
   - `run(cmd, *, cwd, env_allow, timeout, input_text)` — **enforces `shell=False`**: rejects a string
     command (must be an argv list), rejects argv elements that are not `str`. Runs with a **clean
     environment** built from a caller allowlist plus a small safe default set (`PATH`,
     `SystemRoot`/`WINDIR` on Windows); never inherits the full parent env by default.
   - `git_safe(args, *, cwd, ...)` — hardened git for **untrusted clones**: injects
     `-c core.hooksPath=<null-device> -c core.fsmonitor=false -c protocol.ext.allow=never
     -c core.symlinks=false`, and sets `GIT_TERMINAL_PROMPT=0`, `GIT_CONFIG_NOSYSTEM=1`,
     `GIT_CONFIG_GLOBAL=<null-device>` so a malicious repo cannot run hooks, prompt, or read host config.
   - `SafeSubprocessError` for policy violations; `Result{returncode, stdout, stderr, timed_out, argv}`.
     A timeout returns `timed_out=True` (terminating the child), never hangs. Any unexpected failure is
     surfaced, never swallowed into a success.
   - **Tests** (`tests/scripts/coding-mastery/test_safe_subprocess.py`, same `sys.path` style as
     `test_scope_guard.py`): rejects string command / shell metachars; clean-env excludes a secret var
     unless allowlisted; timeout path; `git_safe` argv contains the hardening flags and a hooks-disabled
     env; non-zero exit captured not raised; CLI exit codes.

2. **Extend `skills/references/finding-validation-runtime.md`** — add a **feasibility verdict ladder**
   (`feasible: true | false | null`) where **`null` falls through to manual analysis and NEVER
   auto-kills** on tool/solver limits, and add **Q2.5 "Authentic at source?"** to the 7-question gate:
   evidence that cites an external source must carry a re-verifiable reference (URL + content hash);
   an external source that cannot be re-verified ⇒ **downgrade**, not silent acceptance. Stdlib framing
   (the hash/verify mechanism is PR-2's `evidence_kit.py`; PR-1 states the rule).

3. **Extend `skills/references/finding-evidence-standards.md`** — add the **CVSS inherent-impact rule**
   for native memory-corruption: a *confirmed, controllable* corruption carries an inherent impact
   ceiling (often code-exec) that CVSS may reflect **only when paired with an explicit feasibility
   verdict**, recording `demonstrated` vs `inherent` severity separately. This refines — does not
   contradict — the existing "a status code is not impact / no inflation" rule: the ceiling is labeled
   and gated, never a silent round-up.

4. **Extend `skills/finding-discipline/SKILL.md`** — add a short **read-first / no-name-guessing**
   discipline ("if a function calls another, read the callee — don't infer behavior from its name") and
   **quote-grounded confidence tiers** (High = direct quote from the artifact; Medium = explicitly
   stated assumption; Low = flagged inference). Add two matching red-flag / rationalization rows.

5. **Agent prompts** — add read-first/no-name-guessing + quote-grounded tiers to
   `agents/reverse-engineer.md` and `agents/security-reviewer.md` (the latter already has a Confidence
   line; extend its definition to the quote-grounding standard).

6. **`skills/exploit-development/SKILL.md`** — add a **cached exploit-context** note (fingerprint
   target/libc/checksec **once** and reuse; do not re-run recon each attempt) with a forward pointer to
   the PR-3 empirical feasibility profile that will forbid techniques the target actually blocks.

7. **Report templates** — add a **confidence-level table** (`claim | HIGH/MEDIUM/LOW | rationale`) to
   `templates/report/technical-report.md`, and a feasibility / inherent-vs-demonstrated row to
   `templates/report/finding-record.md` + `templates/exploit/findings/finding-record.md`.

8. **`CLAUDE.md`** — extend the confidence-tier bullet to reference the quote-grounded tiers and the
   feasibility ladder (one-line cross-reference, no behavior change).

### PR-2 — Generator+checker + evidence grounding (DONE)

Delivered on `feat/raptor-adoption` (+72 tests, total 319 passed / 5 z3-skipped):
- `agents/finding-checker.md` — blind checker (artifact-only), distinct from finding-validator.
- `engine/rebuttal.py` — bounded generator↔checker loop as structured state. **Refinement:** a
  separate module that *composes* `LoopDetector` (stall detection) rather than overloading
  `loop_detector.py`, whose single responsibility is rabbit-hole detection.
- `validate_findings.py` — hedge linter (advisory, never drives a tier) + `[EVD-XXX]` citation
  grounding (`--evidence-store`): a dangling or non-VERIFIED citation ⇒ REJECTED (fail-closed);
  `--strict` makes hedge/uncited lint on a CONFIRMED finding fail. Backward compatible.
- `evidence_kit.py` — stdlib `EvidenceStore.verify_all()`; local-snapshot integrity re-hash by
  default, injectable `fetcher` for source re-fetch. **Refinement:** placed in
  `skills/vulnerability-analysis/scripts/` (next to the gate consumer) not incident-response, to
  avoid a cross-skill import; IR/PR-3 can `sys.path` it like `engine.py` does.
- `variant_hunt.py` + `references/variant-hunting.md` — seed→tree-sweep→qualify→cluster-by-root-cause;
  FPs retained, excluded from recommendation.
- `path_conditions.py` (+ `taint_trace.py` guard emission) — branch guards → tri-state feasibility;
  `false` only on a sound UNSAT, a solver/parse limit is `null` (manual), never `false`.
- `frida_universal.js` JSONL `emit()` + `merge_runtime_evidence.py` — runtime sink-executed →
  `proof.runtime_sink_executed` (reachability booster, not a class-confirm).
- Wired into `/engage.gate` (evidence_kit verify + validate_findings `--evidence-store --strict`);
  finding-validator Q3 notes the runtime artifact.

**Stale-analysis correction (carried from PR-1):** the workflow's file-existence assumptions were
based on a snapshot; every PR-2 touch-point was re-read against the live tree before editing.

**Adversarial verification (two red-team passes, the repo discipline):** pass 1 confirmed 16
fail-open/bypass/unsoundness/crash issues across all components (each with a runnable repro +
independent verification); pass 2 — run after the fixes — confirmed the 16 were closed and found 8
more, INCLUDING a HIGH bypass the first round of fixes introduced (a case-fold identity mismatch
between evidence_kit and validate_findings) and an incomplete HIGH fix (variant_hunt suppressing a
tainted var on a sanitizer's RHS). All 24 are fixed, each locked by a regression test, both HIGH
repros re-verified closed. evidence_kit is now the single source of truth on id case (case-insensitive
dedup) and never trusts a loaded status; variant_hunt binds sanitization to the LHS assignment target;
safe_subprocess kills the whole process subtree (POSIX killpg / Windows Job Object KILL_ON_JOB_CLOSE,
best-effort with taskkill fallback) so a timeout is bounded even with a pipe-holding grandchild.
363 tests pass.

### PR-3 — Crash→exploitability pipeline + commands (high effort, needs devcontainer)

`.devcontainer/` with **scoped caps** (`CAP_SYS_PTRACE`/`SYS_PERFMON`, never `--privileged`, never
mount `~/.claude`); `rr-time-travel.md` + `rr_root_cause.sh`; `coverage-reachability.md` + gcov/trace
artifact kind in the harness; `exploit_context.py` + `feasibility_profile.py` (empirical mitigation
matrix); `/engage.crash` orchestration. Then follow-on commands under the single `/engage.*` namespace:
`cve_diff.py`/`/engage.cvediff`, `model_scorecard.py`/`/engage.scorecard`,
`threat-model-discipline`/`/engage.threatmodel`, and the OSS-forensics kit (reusing
`superpowers:dispatching-parallel-agents`, BigQuery isolated as optional).

## Do NOT copy

Pydantic + requests + google-cloud-bigquery stack (re-implement stdlib); hard
BigQuery/`GOOGLE_APPLICATION_CREDENTIALS` prerequisite; the 8-stage lettered state machine + numbered
MUST-GATEs; SHA-256 whole-repo `checklist.json` FULL-COVERAGE gate; auto-PoC-during-validation /
fully-autonomous scan→exploit→patch loop; `/patch` without an `action_guard` gate; filename-presence
state machine (`hypothesis-YYY.md`); the 5-agent forensics orchestrator wholesale; `--privileged` +
binding `~/.claude` into the container; `/raptor-*` aliasing + the <500-token SKILL.md cap;
`libexec/raptor-*` monolithic engine + `self_improvement_prompt.md`; Perfetto GUI + the magic 0–10
proximity integer; Coccinelle site-enrichment + a standalone `/codeql` build command.

## Standing constraint

`scope_guard` and the authorization boundary stay. No script is built to deliberately reach
out-of-scope or unauthorized targets; `scope.json` is operator-defined per engagement.

## Keep / Do-not-regress

Boolean-driven `validate_findings.py` tiers; PASS/KILL/DOWNGRADE `finding-validator`; mandatory
structured fields + templated records; bounded autopilot; `engagement-memory`;
`scope_guard`/`action_guard`; angr/Triton/Z3; the thin-router + `references/` + `scripts/` skill model;
pytest + CI on every new script.
