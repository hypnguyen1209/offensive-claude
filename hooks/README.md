# Hooks — degradation modes

The plugin ships one Claude Code hook. This table (adjacent to `hooks.json`, which is
JSON and can't carry comments) records each hook's **degradation mode** so the safety
posture is explicit and reviewable.

| Hook | Event | Purpose | Degradation mode | Rationale |
|------|-------|---------|------------------|-----------|
| `session-start` | `SessionStart` (`startup\|clear\|compact`) | Inject the `using-offensive-claude` dispatcher so skill-invocation discipline is set before any action | **FAIL-OPEN** — if the dispatcher can't be read/emitted, the session still proceeds (`exit 0`, risky read guarded with `\|\| echo`) | Context injection is a convenience, not a control. `SessionStart` cannot block a session anyway. Better to run without the pointer than to wedge the session. |
| `run-hook.cmd` | (wrapper) | Cross-platform polyglot launcher that finds `bash` and runs the named hook | **FAIL-OPEN** — if no `bash` is found it `exit /b 0` (plugin works, just without injection) | Same reasoning: a missing shell must not break the session. |

## Fail-open vs fail-closed

Hooks here are **fail-open by design** because they only *inject context*. This is the
deliberate opposite of the runtime **safety guards**, which are **fail-closed**:

| Component | Mode | On error / uncertainty |
|-----------|------|------------------------|
| `hooks/session-start`, `run-hook.cmd` | fail-open | skip injection, session proceeds |
| `_lib/scope_guard.py` | fail-closed | out-of-scope / unparseable target → **block** |
| `_lib/action_guard.py` (`decide`, `decide_command`, `decide_config_edit`) | fail-closed | mutating / destructive / config-edit / stat-error → **require_approval or block** |
| `_lib/safe_subprocess.py` | fail-closed | policy violation → raise; timeout/missing binary → non-success `Result`, never a silent "ok" |
| `validate_findings.py` | fail-closed | missing evidence / ungrounded → reject (no `[CONFIRMED]`) |

Rule of thumb: **anything that decides whether an action may go out is fail-closed;
anything that only enriches the model's context is fail-open.**

## Subagent discipline

There is intentionally **no** `SubagentStart` hook. That event is read-only in Claude
Code (it cannot inject `additionalContext` into a spawned subagent), so the dispatcher
cannot be re-emitted to forked subagents via a hook. Instead each agent definition in
`agents/*.md` carries an inline "Operating discipline (you run forked)" block that
restates the non-negotiables (scope, evidence bar, OPSEC, `TERMS.md`).
