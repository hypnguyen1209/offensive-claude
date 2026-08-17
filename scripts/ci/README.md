# CI consistency & safety gates

These are **fail-closed** checks (exit non-zero on any violation) that guard the plugin's
load-bearing invariants. They are pure stdlib, model-free, and network-free, and run as the
`consistency` job in [`.github/workflows/tests.yml`](../../.github/workflows/tests.yml). Each has a
sibling test under [`tests/scripts/ci/`](../../tests/scripts/ci/).

| Script | Guards | Fails when |
|--------|--------|-----------|
| `check_invariants.py` | Load-bearing safety **phrases** stay identical across their copies (ponytail canary). | A copy of an invariant string (e.g. "a status code is not impact") drifts or goes missing. |
| `check_constitution.py` | Every agent + `CLAUDE.md` **state their guardrails** (structure, not prose). | An agent lacks a scope reference (if it can touch targets) or the evidence/OPSEC guardrail; `CLAUDE.md` drops a doctrine substring. |
| `verify_skills_lock.py` | Tamper-evident **lockfile** over the whole skill tree. | Any `skills/<name>/` content changed, a skill was added, or one was removed, without re-pinning `skills-lock.json`. |
| `check_subprocess_discipline.py` | **Shell-injection ban** across production `.py`. | A real `os.system` / `os.popen` / `subprocess(..., shell=True)` call appears without a reviewed `# noqa: subprocess-discipline - <reason>` pragma. |
| `agent_eval_selftest.py --selftest` | The **scored judge paths** (`model_scorecard`, `rebuttal`) behave to a frozen golden baseline. | A threshold/logic regression flips a golden verdict (trust calibration or rebuttal convergence). |

## Updating after an intentional change

- **Skill edited on purpose** → `python scripts/ci/verify_skills_lock.py --update`, then commit the
  lockfile diff *alongside* the change so a reviewer sees exactly what content moved.
- **New safety phrase / new agent** → add the invariant to `check_invariants.py` (or the guardrail
  group to `check_constitution.py`) in the same PR that introduces the language.
- **Legitimate `shell=True`** (fixed local command, no external input) → add
  `# noqa: subprocess-discipline - <why it is safe>` on the call line. A **bare** pragma (no reason)
  is itself a violation — the justification is forced into the diff.

## Baseline isolation (why the self-test uses a throwaway DB)

`agent_eval_selftest.py` exercises `engine/model_scorecard.py`, which persists verdict outcomes to a
sqlite DB. The operator's **real** track record lives at `~/.claude/engagement-memory/scorecard.sqlite`
(overridable via `MODEL_SCORECARD_DB`). An eval that recorded its synthetic "6 misses in 200"
scenarios into that real DB would **poison the very track record it is meant to check** — the next
`is_trusted()` in a live engagement would read fabricated misses.

So the self-test:

1. creates a throwaway temp DB (`tempfile.mkdtemp`), and
2. **asserts in-code** that this temp path is not the real `db_path()` before recording anything —
   if they ever collide it refuses to run (emits a failing `isolation` case) rather than touch the
   baseline.

The rule generalizes: **an evaluation must never write to the store it evaluates.** Any future eval
that scores a stateful judge path must isolate its baseline the same way.
