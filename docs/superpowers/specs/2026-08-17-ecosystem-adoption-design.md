# Design Spec — ecosystem adoption (claude-mem · codegraph · ecc · graphify · ponytail · repomix)

**Date:** 2026-08-17
**Branch:** `feat/ecosystem-adoption`
**Status:** DRAFT — spec approved (all tranches), implement incrementally, review between tranches.

## Goal

Study six mature Claude-Code / AI-agent ecosystem projects and adopt the *genuinely transferable*
engineering into offensive-claude **without** copying their off-mission scaffolding (cross-harness
adapter matrices, HTTP daemons, vector DBs, cloud/SaaS tiers, native Rust kernels, desktop GUIs,
LOC-optimizing behavioral dials). Every adoption lands on our existing thin-router + `references/` +
`scripts/` model, stays **stdlib-only / Python-first**, ships **behind existing gates**, keeps the
`scope_guard`/`action_guard` authorization boundary intact, stays **single-harness (Claude Code)**,
and is **covered by tests + CI**. We adopt *patterns and mechanisms*, not vendored code.

## Source-repo map (what each gives us)

| Repo | What it is | Net-new for us | Already stronger (don't regress) |
|---|---|---|---|
| **claude-mem** | persistent memory, observer sub-agent, SQLite/FTS5 | 3-layer retrieval, FTS5 finding store, fail-open/closed hook policy, `<private>` boundary redaction, hook-IO CI linter, content-hash dedup | our redaction doctrine, engagement-memory BM25 |
| **codegraph** | Rust tree-sitter → SQLite code-graph | reverse-reachability variant hunting, `affected` diff→sinks, provenance-tagged edges, "errors teach abandonment" tool-UX, agent-eval A/B, generated-file demotion | validate_findings tiers, evidence_kit |
| **ecc** | cross-harness "agent OS", hardened hooks + CI validators | destructive-command tokenizer, supply-chain IOC scanner, Unicode/ASCII-smuggling scanner, config-protection hook, constitution-as-CI-test, hash-chained audit log, tiered hook profiles | scope/action guards, rebuttal loop |
| **graphify** | zero-LLM AST → knowledge graph | EXTRACTED/INFERRED/AMBIGUOUS edge provenance, discrete confidence rubric, path-tracer, community→attack-surface map, vocabulary-grounding, shrink-guard writes, skill drift-check | quote-grounded confidence (per-finding), source-to-sink skill |
| **ponytail** | one behavioral skill → 20 harnesses from one source | SubagentStart re-injection, invariant-phrase canary, rigorous skill benchmarking + judge protocol + baseline isolation, self-testing instruments | SessionStart dispatcher |
| **repomix** | pack codebase into AI-friendly artifact | secretlint pre-emit gate, urlRedact (CWE-532), scoped repo-packing for audit, skills-lock.json, git `--end-of-options` hardening | http_creds/redact_headers masking |

**Convergent external validation:** graphify, codegraph, ponytail, and ecc independently arrived at
the two ideas offensive-claude already champions — **provenance/grounding as a first-class attribute**
and **adversarial, quote-citing, self-tested judges**. Each supplies a concrete mechanism to harden
what we already do; T2 captures those.

## Verified gap (pre-work finding)

`hooks/hooks.json` defines **only `SessionStart`** (`matcher: startup|clear|compact`). The
`using-offensive-claude` dispatcher and discipline skills are injected into the parent thread but
**not into dispatched subagents** (`finding-validator`, `finding-checker`, hunt agents). Per
ponytail issue #252, SessionStart context never reaches subagents — so our discipline-enforcement
agents may run discipline-unaware. Fixed in PR-1 by embedding a forked-subagent discipline block in
each agent `.md` (the hook route is not viable — see item 5).

## Design invariants (apply to every PR)

1. **Stdlib-only, Python-first.** Port *catalogs/regexes/logic*, never a Node/Rust dependency. Match
   `scope_guard.py` house style: `main(argv)` exit codes, dataclass results, fail-closed.
2. **Fail-closed for safety, fail-open for capture.** A safety gate (scope/action/config-protection)
   that errors must **block**; a best-effort capture/enrichment (memory, graph, dedup) that errors must
   **degrade, never crash the operator's session** (claude-mem exit-code policy). Each hook declares
   which it is.
3. **Never log the secret.** Any scanner reports **count + location only**, never the matched value
   (repomix `securityCheckWorker` rule). Extends "secrets never hit logs".
4. **Provenance is stamped at derivation and never promoted** (graphify rule). No post-processing
   upgrades an INFERRED hop to EXTRACTED.
5. **Single harness.** No cross-agent adapter dirs. One canonical source per rule; CI guards drift.
6. **Tests gate changes.** Every new script has a `tests/scripts/...` sibling; CI (`tests.yml`) runs
   them. New CI validators are themselves byte-compile + unit covered.

---

## PR plan

### PR-1 — T1 Safety hardening (stdlib, no toolchain)

Highest fit to the plugin's identity. Pure-additive except the two hook/agent wirings.

1. **`_lib/cmd_parser.py`** (NEW + tests) — bypass-resistant destructive-command tokenizer, porting the
   *logic* of ecc `gateguard-fact-force.js` + `shell-substitution.js`/`shell-split.js`:
   `is_destructive(cmd)` handles combined/split `rm -rf` flags, `git push --force` (vs
   `--force-with-lease`, `+refspec`), `reset --hard`, `clean -f`, `switch -C`, `find -exec rm`, SQL
   `drop/truncate`, `dd`, **subshell explosion** (`$(...)`, backticks, `{ }`, `( )` via BFS body
   collection), quoted-command-word and `sh -c`/`bash -c` wrapper bypasses. Returns a structured
   verdict `{destructive: bool, reasons: [...], matched: [...]}` — never the raw secret/arg values in
   logs. Cite the GHSA fixes in comments.
   - **Red-team pass hardening:** an inline adversarial pass found runner-prefix and eval bypasses
     (`exec rm -rf /`, `sudo rm -rf /`, `timeout 5 rm -rf /`, `env A=b rm -rf /`, `xargs -0 rm -rf`,
     `sudo sh -c 'rm -rf /'`, `eval "$(printf 'rm -rf /')"`) that all classified *safe*. Fixed by
     `_strip_runners()` (drops a runner + its flags/env-assigns/numeric args and re-classifies the
     wrapped **token list** — never re-stringified, so a quoted `sh -c` payload survives) and an
     `eval` branch (re-scan the arg + flag eval-of-substitution for manual review). Benign runners
     (`sudo apt update`, `timeout 5 curl …`, `env PATH=/x ls`) stay unflagged. Regression-tested.
   - **Wire into `action_guard.py`:** the existing "mutating verb" classifier calls `cmd_parser` so a
     `sh -c 'rm -rf /'` or `$(...)`-wrapped destructive command is caught, not just a bare `rm`. Keep
     backward-compatible (only tightens; a previously-blocked call stays blocked).

2. **`_lib/secret_scan.py`** (NEW + tests) — fail-closed pre-emit secret scanner porting repomix's
   secretlint *catalog* (AWS/GCP/GitHub/npm/Slack tokens, private-key blocks, JWT, generic
   high-entropy assignments) as Python regexes with ReDoS-bounded patterns. `scan(text) ->
   [Hit{rule, line, col}]` (**value never included**). `redact_url(text)` + `redact_error(text)` port
   repomix `urlRedact.ts` (scheme://token@host, scp-style user:pass@host, credential query params —
   CWE-532), ReDoS bounds preserved. Complements `redact_headers.py`/`http_creds.py` (which mask known
   header names) with content-level credential detection over arbitrary text.
   - **Wire:** `redact_headers.py` gains a `redact_text()` passthrough to `secret_scan.redact_*`; route
     subprocess stderr surfacing (safe_subprocess Result → any log) through `redact_error`.

3. **`_lib/unicode_scan.py`** (NEW + tests) — port ecc `check-unicode-safety.js` taxonomy: zero-width,
   bidi override, **Unicode Tag-block U+E0000–E007F ASCII-smuggling**, invisible-math, Hangul-filler.
   `scan(text) -> [Hit]`; `strip(text) -> clean` (auto-fix). CLI `--write`. Purpose: run over incoming
   untrusted proxy/fetched content and over authored skills/findings before they enter context/report.
   Prompt-injection defense for our untrusted-content threat model.

4. **`config-protection` decision in `action_guard.py`** (port ecc `config-protection.js` concept, not
   a new hook) — block **edits** (allow first-time create) to engagement-critical config:
   `.engage/scope/scope.json`, ROE files, gate/validation config, `settings.json` deny lists. An agent
   widening scope to "pass" a gate is exactly this failure mode. Fail-closed on stat error except
   ENOENT.

5. **Subagent discipline re-injection** — RESOLVED via the documented fallback, not a hook. The
   installed Claude Code exposes `SubagentStart`, but it is a **read-only** event: it cannot inject
   `additionalContext` or otherwise modify a spawned subagent (verified against
   code.claude.com/docs/en/hooks — "Can block? No", and the docs explicitly direct context-to-subagent
   needs to `.claude/rules/` or the subagent's own frontmatter). So the hook route is dead. Instead,
   each agent `.md` (`redteam-planner`, `exploit-researcher`, `security-reviewer`, `reverse-engineer`,
   `ai-researcher`, `network-analyst`) now carries an "Operating discipline (you run forked)" block
   stating the dispatcher is not inherited and restating the non-negotiables (scope via
   `scope_guard.py` + `.engage/scope/scope.json`, the per-class evidence bar, OPSEC/secret-redaction,
   `TERMS.md`). `finding-validator`/`finding-checker` already saturate scope (Q1) + evidence (Q2) so
   they were left as-is. This is fail-safe (static text, no runtime). Closes the verified gap.

6. **Codify fail-open/closed per hook** — DONE. Header comment block in `hooks/session-start` +
   new `hooks/README.md` (the JSON-adjacent doc, since `hooks.json` can't carry comments) with a
   per-hook degradation-mode table and the fail-open (context injection) vs fail-closed (safety
   guards) rule of thumb. Matches claude-mem exit-code policy.

7. **`git_safe` `--end-of-options` audit** — DONE with a correction. `GCM_INTERACTIVE=never` was
   already set in `git_safe_env()`. Blind terminator insertion inside `git_safe()` is *unsafe* — it
   cannot know where positionals begin (`['-C', repo, 'log', rev]` has no fixed boundary), so
   inserting `--`/`--end-of-options` at a guessed index would corrupt the argv. Instead added
   `git_rev_argv(subcommand, refs, paths)`: the caller that knows which tokens are user-controlled
   declares the boundary, and the helper places refs after `--end-of-options` and paths after `--`
   so a ref/path beginning with `-` can never be parsed as an option. `git_clone_safe` already uses
   `--`. Tests assert the terminators appear and a leading-dash ref stays behind them.

**Tests:** one `tests/scripts/coding-mastery/test_*.py` per new module (cmd_parser, secret_scan,
unicode_scan) + action_guard integration cases + git_safe terminator assertions. Bypass-corpus for
cmd_parser (the `sh -c`, `$(...)`, split-flag cases). Count-only assertion for secret_scan (never
emits the value).

### PR-2 — T3 Consistency / CI (ends the manual parity passes)

Directly kills the recurring "manual CLAUDE/README/skills parity pass" recorded in memory.

1. **`scripts/ci/check_invariants.py`** (NEW + tests) — port ponytail `check-rule-copies.js` canary:
   a pinned list of load-bearing safety substrings (evidence bars per class, `[CONFIRMED]` proof rule,
   confidence-tier definitions, scope-guard invocation rule) asserted to survive **verbatim** across
   `CLAUDE.md`, `skills/references/finding-evidence-standards.md`, `skills/references/finding-validation-runtime.md`,
   and the docstring/messages of `validate_findings.py`. Fails CI on drift.

2. **`scripts/ci/check_constitution.py`** (NEW + tests) — port ecc `agent-instruction-safety.test.js`:
   assert each agent `.md` + `CLAUDE.md` **contain required guardrail headings/patterns** (e.g. every
   agent that touches targets states a read-only-by-default + explicit-approval boundary; finding
   agents state the evidence bar). Turns Output Standards from prose into a gated assertion.

3. **`skills-lock.json` + `scripts/ci/verify_skills_lock.py`** (NEW + tests) — port repomix lockfile
   *shape*: `{version, skills: {<name>: {path, sha256}}}` over our first-party skills (reuse
   `evidence_kit` hashing). Detects skill drift + gives supply-chain integrity (ties to our own
   `cicd-supply-chain` posture). CI verifies lock matches tree; a `--update` regenerates.

4. **`scripts/ci/check_subprocess_discipline.py`** (NEW + tests) — port claude-mem hook-IO linter idea:
   grep active scripts and fail if any `subprocess.` / `os.system` / `os.popen` call bypasses
   `safe_subprocess`, or any active network call bypasses `action_guard`. Comment-stripped to avoid
   doc false-trips. Pure-Python, high leverage for a safety-critical codebase.

5. **Agent-eval self-test discipline + baseline isolation** (adopt ponytail/codegraph *methodology*,
   minimal harness) — a `tests/` harness convention: any scored/paid model-judge path
   (`model_scorecard`, `rebuttal`, `finding-validator`) ships a deterministic `--selftest` that must
   pass a planted-good + planted-bad reference **before** any scored run ("instruments broken; refusing
   to spend"). Document the **baseline-isolation caveat** (ponytail's retraction): any A/B must isolate
   the plugin (`--setting-sources project,local` + per-arm `--plugin-dir`) or the SessionStart
   dispatcher contaminates the control. This PR adds the self-test scaffolding + doc; full A/B harness
   is optional follow-on.

6. **Wire all four validators into `.github/workflows/tests.yml`** as a `lint`/`consistency` job.

### PR-3 — T2 Finding-quality / provenance (reinforces the core) — DONE

Concrete mechanisms for systems we already have (quote-grounded confidence, adversarial judges).

> **Status: implemented.** (1) per-hop provenance gate — `provenance.py` + `_apply_provenance_cap` in
> `validate_findings.py` (all-EXTRACTED ⇒ CONFIRMED allowed; any INFERRED/AMBIGUOUS/empty caps to
> POSSIBLE; never promotes/rescues REJECTED). (2) discrete confidence + (3) formal judge protocol —
> `engine/judge_protocol.py` (five buckets or AMBIGUOUS, pinned decoding, versioned+fingerprinted
> rubric, `[EVD-XXX]`-cited accepts, `cache_key` invalidates on rubric bump, `is_calibrated` strict
> PASS>KILL gate), wired into `finding-validator`/`finding-checker` prompts + `agent_eval_selftest.py`
> golden scenarios + `skills/references/llm-judge-protocol.md`. (4) `finding_dedup.py` content-hash
> dedup (within-phase window). (5) `vocab_gate.py` executable vocabulary-grounding (fail-closed). (6)
> Cohen's kappa in `model_scorecard.py` (`record-pair`/`kappa`, dialect canonicalization, degenerate ⇒
> None not 1.0, informational — does not feed `is_trusted`). All TDD-green; 688 tests; 5 CI gates pass.

1. **Per-hop provenance enum** — extend `taint_trace.py` / `path_conditions.py` / source-to-sink
   records so **each hop** carries `provenance ∈ {EXTRACTED, INFERRED, AMBIGUOUS}` (graphify rule:
   literal call = EXTRACTED; resolver/name-bridged = INFERRED; unresolved indirect = AMBIGUOUS), and a
   **path is only as strong as its weakest hop**. Gate: `[CONFIRMED]` requires an **all-EXTRACTED**
   reachability path; any INFERRED hop caps at `[POSSIBLE]`. Enforce in `validate_findings.py`
   (fail-closed). Forbid provenance promotion in post-processing (test it).

2. **Discrete confidence rubric** — replace any continuous 0–1 confidence in judge prompts/records
   with graphify's five buckets (0.95/0.85/0.75/0.65/0.55) each with a one-line rubric, "if none fit,
   mark AMBIGUOUS." Defeats model score-collapse. Update `finding-validator`/`finding-checker` prompts
   + the record schema.

3. **Formal LLM-judge protocol** (ponytail `judge.py`) — for `finding-validator`/`finding-checker`:
   pinned model, temperature 0, a **versioned rubric string emitted into the verdict record**,
   mandatory citation (we already require `[EVD-XXX]`), and a **judge calibration self-test** (rank a
   planted PASS strictly above a planted KILL reference or the batch is "NOT TRUSTWORTHY"). Composes
   with the Wilson-bound `model_scorecard`. Add **cache invalidation keyed by rubric version**
   (graphify): cached verdicts re-derive when the rubric changes.

4. **Finding content-hash dedup** (claude-mem) — a `content_hash = sha256(scope∥title∥sink∥cwe)[:16]`
   on finding records; dedup across phase re-runs, `/engage.pickup` resumes, and rebuttal iterations so
   the same vuln isn't recorded N times. **Window rule:** a legitimately re-confirmed finding in a
   *later phase* is not silently dropped — dedup is within-phase / within-run.

5. **Executable vocabulary-grounding** (graphify Step 0) — a `scripts/vocab_gate.py` that extracts the
   actual symbol/token vocabulary from the in-scope target and constrains audit queries to it ("select
   from this list; do not invent tokens; if nothing matches, stop"). Mechanizes the existing
   "never name-guess" rule. Referenced from `vulnerability-analysis` / `source-to-sink-tracing`.

6. **Kappa-agreement metric** (graphify BENCHMARKS) — `model_scorecard` records blind-judge agreement
   (Cohen's kappa) between `finding-validator` and `finding-checker` as a reliability signal alongside
   the miss-rate.

### PR-4 — T4 Source-to-sink code-graph (biggest new capability, L)

Scoped, stdlib+tree-sitter (Python bindings we already reference via CodeQL/Semgrep skills — no native
kernel). Candidate-generation feeding existing verification; never treated as proof.

1. **`scripts/codegraph/build_graph.py`** — tree-sitter (or fall back to existing Semgrep/CodeQL
   output) → a **Python `sqlite3` nodes/edges/unresolved_refs schema** (codegraph `schema.sql` shape:
   symbols with kind/qualified_name/file:line/signature; edges with kind + **provenance** column +
   metadata JSON; FTS5 mirror; `UNIQUE(source,target,kind,line,col)` dedup). Two-phase extract→resolve
   with a retryable `unresolved_refs` table. Content-hash incremental reindex + **stable
   content-addressed node IDs** so `[EVD-XXX]` anchors survive re-scans. **Scope-gated** by
   `scope_guard`. **Shrink-guard write** (graphify): refuse to overwrite a good graph with a
   node-count-smaller one.

2. **`scripts/codegraph/traverse.py`** — reverse-reachability (`callers`/`impact_radius`, excluding
   `contains` edges to avoid explosion) for **variant hunting** (augments `variant_hunt.py`);
   `path A B` shortest-path tracer printing **per-hop relation + provenance** for **source-to-sink**
   (feeds PR-3's per-hop provenance gate). Directed graph for taint orientation (graphify caveat: must
   use `--directed`). Cite the **edge SITE** (call line), not the def line (graphify `affected.py`).

3. **`scripts/codegraph/affected.py`** — `git diff --name-only | affected` → downstream
   security-sensitive sinks. **Augments `/engage.cvediff` + `patch-diffing-nday`**: given a CVE fix
   commit, which sinks are downstream.

4. **`scripts/codegraph/attack_surface.py`** — community detection (Leiden/Louvain via graspologic *or*
   a deterministic connected-components fallback) → subsystems/trust-zones; **god-nodes** (choke
   points / high-value targets); **surprising_connections** (cross-community edges = trust-boundary
   crossings); auto-seed a validation worklist. Feeds `threat-model-discipline` + surface mapping.
   Generated/vendored-file **demotion** in ranking (codegraph) so audits lead with hand-written code.

5. **`scripts/recon/pack_target.py`** — scoped repo-packing (repomix pipeline *concept*) into a bounded,
   token-counted, structure-first `.engage/recon/target-pack.md` for an audit agent, with the
   **secret_scan gate ON** (PR-1) so a target's live secrets never enter context/report. Signature-only
   "compress" mode (tree-sitter signatures, degrade-to-full-on-parse-error) for large targets.

**"Errors teach abandonment" (codegraph):** every codegraph CLI returns **success-shaped guidance**
for recoverable states (not-indexed, not-found), reserving error exit for genuine "stop trying".

### PR-5 — T5 Memory scaling (M/L)

1. **3-layer finding retrieval** (claude-mem) — replace "inject all prior findings" with
   `finding-search` (compact index: id/cwe/severity/title) → `timeline(anchor)` →
   `get_findings(ids=[...])` full-fetch. Attacks long-engagement context bloat.

2. **`findings.db` FTS5 store** (claude-mem `schema.ts`) — Python `sqlite3` + FTS5 (`porter unicode61`),
   trigger-synced mirror, **count-mismatch auto-rebuild**, phase/scope isolation via `RAISE(ABORT)`
   trigger (project-guard pattern). Backs the 3-layer retrieval and `engagement-memory`. No new dep
   (FTS5 is in stock CPython).

3. **`WORKING-CONTEXT.md`** (ecc) — a living, human-readable engagement-state file (current truth /
   constraints / active queues) surfaced by `/engage.status`, distinct from the machine finding store.

4. **Token-economics accounting** (claude-mem `TokenCalculator`) — track "tokens to rediscover" vs
   "tokens to read compressed memory" per phase; enforce a recall budget; **telemetry from counts/enums
   only, never content**.

5. **`<private>` boundary tag** (claude-mem `tag-stripping`) — operators mark engagement content that
   must never persist into memory/findings/report; stripped before any write. Respect the
   absent-vs-empty distinction (don't conflate missing data with redacted).

---

## Explicitly NOT adopting (and why)

- **Cross-harness adapter matrices** (ecc's 12 mirror dirs, ponytail's 15 editor tiers, graphify's
  15-assistant installer, codegraph's multi-platform bundler). We are single-harness by design; the
  drift/maintenance tax is unjustified, and a rules-file host cannot run our executable safety layer —
  it would ship a hollow, unsafe subset.
- **Long-running HTTP daemon / worker** (claude-mem worker-service, Express, per-user port). Adds a
  listening port + background lifecycle to defend — opsec-hostile. Engine stays synchronous per gate.
- **Vector DB / embeddings** (claude-mem ChromaDB, graphify semantic pass). FTS5 covers a finding
  corpus far smaller than a coding-history corpus; the sync-consistency + runtime deps aren't worth it.
- **Cloud/SaaS tier, telemetry infra** (claude-mem Postgres/auth, codegraph telemetry-worker,
  ecc AgentShield-Pro/MRR scaffolding). Off-mission; any outbound endpoint is an anti-pattern for
  air-gapped authorized engagements. Adopt telemetry *privacy design* (allowlist, DO_NOT_TRACK,
  local-only) only if stats are ever wanted.
- **Native Rust/WASM tree-sitter kernel** (codegraph-kernel, repomix tree-sitter-wasms). We lean on
  Semgrep/CodeQL/tree-sitter-python we already integrate; we adopt the *graph model + provenance +
  traversal*, not the parser machinery + per-grammar version-pinning burden.
- **Desktop GUI** (ecc Tkinter dashboard). `/engage.status` + engine trace cover run-state better.
- **LOC intensity dial + statusline** (ponytail mode-tracker). Our behavior is phase/skill-driven, not
  one global knob.
- **Obfuscated inline hook one-liners** (claude-mem hooks.json bootstrap). Steal the robustness goals
  (find newest non-orphaned plugin root, cross-platform), keep hook commands as readable script files.

## Sequencing & review gates

Implement **PR-1 → PR-2 → PR-3 → PR-4 → PR-5**, one at a time, each: TDD, `pytest` green, byte-compile
clean, **pause for user review before the next**. PR-1 and PR-2 are the recommended first cut (highest
fit + ends the parity passes). Each PR ends with the repo discipline: a red-team/adversarial pass over
the new safety-relevant code before it's considered done.

## Test/CI impact

Every new script gets a `tests/scripts/...` sibling; the four PR-2 validators are added as a CI job;
byte-compile coverage extends to `scripts/ci/` and `scripts/codegraph/`. Target: no regression on the
existing 491-test baseline; each PR reports its net test delta.
