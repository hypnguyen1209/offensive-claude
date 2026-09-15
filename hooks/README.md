# Hooks — degradation modes

The plugin ships two Claude Code hooks. This table (adjacent to `hooks.json`, which is
JSON and can't carry comments) records each hook's **degradation mode** so the safety
posture is explicit and reviewable.

| Hook | Event | Purpose | Degradation mode | Rationale |
|------|-------|---------|------------------|-----------|
| `session-start` | `SessionStart` (`startup\|clear\|compact`) | Inject the `using-offensive-claude` dispatcher so skill-invocation discipline is set before any action | **FAIL-OPEN** — if the dispatcher can't be read/emitted, the session still proceeds (`exit 0`, risky read guarded with `\|\| echo`) | Context injection is a convenience, not a control. `SessionStart` cannot block a session anyway. Better to run without the pointer than to wedge the session. |
| `subagent-start` | `SubagentStart` | Best-effort inject the forked-subagent discipline (scope / evidence bar / OPSEC / `TERMS.md`) into every dispatched subagent, as defense-in-depth | **FAIL-OPEN and NON-LOAD-BEARING** — `exit 0` always; the inline per-agent discipline blocks remain the authoritative guarantee | The subagent carries the non-negotiables from its own definition regardless. This hook only adds a runtime reminder; if the platform ignores `SubagentStart` context it is a harmless no-op. |
| `run-hook.cmd` | (wrapper) | Cross-platform polyglot launcher that finds `bash` and runs the named hook | **FAIL-OPEN** — if no `bash` is found it `exit /b 0` (plugin works, just without injection) | Same reasoning: a missing shell must not break the session. |

## Fail-open vs fail-closed

Hooks here are **fail-open by design** because they only *inject context*. This is the
deliberate opposite of the runtime **safety guards**, which are **fail-closed**:

| Component | Mode | On error / uncertainty |
|-----------|------|------------------------|
| `hooks/session-start`, `hooks/subagent-start`, `run-hook.cmd` | fail-open | skip injection, session/subagent proceeds |
| `_lib/scope_guard.py` | fail-closed | out-of-scope / unparseable target → **block** |
| `_lib/action_guard.py` (`decide`, `decide_command`, `decide_config_edit`) | fail-closed | mutating / destructive / config-edit / stat-error → **require_approval or block** |
| `_lib/safe_subprocess.py` | fail-closed | policy violation → raise; timeout/missing binary → non-success `Result`, never a silent "ok" |
| `validate_findings.py` | fail-closed | missing evidence / ungrounded → reject (no `[CONFIRMED]`) |

Rule of thumb: **anything that decides whether an action may go out is fail-closed;
anything that only enriches the model's context is fail-open.**

## Subagent discipline

Subagents do **not** receive the SessionStart `using-offensive-claude` dispatcher, so the
non-negotiables have to reach them another way. Two layers, in priority order:

1. **Authoritative (always present):** each agent definition in `agents/*.md` carries an inline
   "Operating discipline (you run forked)" block that restates the non-negotiables (scope,
   evidence bar, OPSEC, `TERMS.md`). This is the guarantee — it is part of the agent's own prompt
   and does not depend on any runtime feature.
2. **Best-effort (defense-in-depth):** the `subagent-start` hook re-emits the same non-negotiables
   as `SubagentStart` `additionalContext`. Newer Claude Code versions (validated on 2.1.272's
   manifest tooling) expose `SubagentStart` as a writable event; older versions treated it as
   read-only. Because the capability is version-dependent and was **not empirically confirmed on
   this project's runtime**, the hook is deliberately **non-load-bearing**: if the platform ignores
   the injected context it is a harmless no-op, and layer 1 still holds.

> To confirm layer 2 works on your install: add a `SubagentStart` hook that injects a unique
> sentinel string, spawn any subagent, and ask it to echo back tokens it can see. If the sentinel
> appears, `additionalContext` injection is active. See the caveat in Anthropic's hooks docs — the
> subagent's task prompt itself is not yet passed to the hook input.
