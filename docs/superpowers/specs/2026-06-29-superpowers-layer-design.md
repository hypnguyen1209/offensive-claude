# Design Spec — Superpowers-style Discipline Layer for offensive-claude

**Date:** 2026-06-29
**Branch:** `feat/superpowers-layer`
**Status:** Approved — in implementation

## 1. Goal

Make offensive-claude *feel and install like* obra/superpowers by adding superpowers'
**discipline layer** on top of the existing 31 domain skills (without rewriting their content):
a SessionStart-injected dispatcher, offensive process/discipline skills, trigger-based skill
descriptions, and installable-plugin packaging.

What makes superpowers work (and what we mirror):
- A **SessionStart hook** injects a **dispatcher skill** into every conversation, enforcing
  "if even 1% chance a skill applies, invoke it before acting."
- **Process/discipline skills** govern *how* to work, distinct from domain skills.
- **Descriptions are `Use when…` triggers only** (never workflow summaries) so the dispatcher
  loads the right skill.
- **Red-flags / rationalization tables + flowcharts** resist shortcutting under pressure.
- Distributed as a **Claude Code plugin** (`plugin.json` + `marketplace.json`).

## 2. Components

### 2.1 Plugin packaging
- `.claude-plugin/plugin.json` — name `offensive-claude`, version, author, homepage, keywords.
- `.claude-plugin/marketplace.json` — single-plugin marketplace (`source: ./`).
- Keep `install.sh` for back-compat.

### 2.2 SessionStart hook + dispatcher (core mechanism, mirrors superpowers)
- `hooks/hooks.json` — SessionStart (matcher `startup|clear|compact`) → `run-hook.cmd session-start`.
- `hooks/run-hook.cmd` — cross-platform polyglot wrapper (Windows cmd → Git Bash; Unix → bash).
- `hooks/session-start` — extensionless bash script: reads `skills/using-offensive-claude/SKILL.md`,
  JSON-escapes it, emits `hookSpecificOutput.additionalContext` (Claude Code) /
  `additional_context` (Cursor) / `additionalContext` (Copilot).
- `skills/using-offensive-claude/SKILL.md` — the dispatcher: invoke-before-acting discipline,
  instruction priority, **authorized-engagement assumption**, red-flags table, routing to
  engagement-flow + the discipline skills + domain skills.

### 2.3 Process / discipline skills (the "how to work" layer)
| Skill | Offensive analog of | Ties to |
|-------|--------------------|---------|
| `engagement-flow` | brainstorming→writing-plans→executing-plans | `/engage.*`, kill chain; flowchart |
| `finding-discipline` | TDD ("no [CONFIRMED] without proof") | `validate_findings`, `finding-validator`; red-flags + rationalization table |
| `scope-discipline` | TDD Iron Law ("no target without authorization") | `scope_guard`, `action_guard`; red-flags + rationalization table |
| `opsec-discipline` | verification-before-completion | `redact_headers`, detection pairing; red-flags |
| `writing-offensive-skills` | writing-skills | conventions for this repo's skills |

### 2.4 CSO description pass
Rewrite each skill's `description:` to `Use when…` trigger format (triggers/symptoms only, no
workflow summary) so the dispatcher selects correctly. Frontmatter-only; domain-skill bodies unchanged.

## 3. Decisions

- **scope_guard / scope-discipline are KEPT.** The framework stays authorization-bounded; the
  dispatcher assumes authorized engagement and routes to scope-discipline before any target
  interaction. `scope.json` is operator-defined per engagement, so legitimate flexibility exists
  without removing the guard. The framework will NOT be built to deliberately target out-of-scope
  assets — that is the authorization boundary and it stays.

## 4. Conventions (from superpowers writing-skills)

- `name` + `description` (max 1024 chars); `description` = `Use when…` triggers, third person, no
  workflow summary.
- Verb-first / gerund names; flowcharts only for non-obvious decisions; red-flags + rationalization
  tables for discipline skills; cross-reference skills by name with **REQUIRED** markers (no `@` links).

## 5. Execution & verification

Build incrementally on `feat/superpowers-layer`, commit per chunk. Verify: `plugin.json` /
`marketplace.json` / `hooks.json` are valid JSON; `session-start` parses (`bash -n`); the existing
175-test pytest suite still passes; frontmatter lint passes.

## 6. Out of scope

- No rewrite of the 31 domain-skill bodies (descriptions only).
- No removal/weakening of scope_guard or any safety control.
