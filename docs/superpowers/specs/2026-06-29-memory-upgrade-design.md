# Design Spec — engagement-memory Upgrade (learning from knowns-dev/knowns)

**Date:** 2026-06-29
**Branch:** `feat/memory-upgrade`
**Status:** Approved — in implementation

## Goal

Close the memory-management gaps in `skills/engagement-memory` while staying **stdlib-only + local
JSONL** (no DB server, embeddings, MCP server, or WebUI). Adopt *ideas* from knowns-dev/knowns
(3-layer model, audit trail, retention/decay, relevance recall) — not its Go/product infrastructure.

## Gaps closed

1. `audit`/`target_profile` types declared in `schemas.py` but never written → wire them.
2. `gc`/`compact` manual only → auto-gc size trigger (patterns stay lossless; only audit log discards).
3. Recall is exact keyword/tag match then impact sort → blend stdlib BM25 + alias expansion.
4. No retention/decay → `status`/`confidence`/`last_verified`/`ttl_days` (never delete knowledge).
5. No per-phase recall injection → budgeted `inject` (top-N, byte cap, auto/debug/off modes).
6. Per-client isolation only via env → global vs per-client scope + review-gated record.

## PR plan (each test-backed, on `feat/memory-upgrade`)

### PR1 — Wire audit + auto-gc + target profiles
- `schemas.py`: `make_audit`/`validate_audit` (action_class ∈ read|write|delete|generate|admin,
  outcome ∈ success|error|denial, dry_run, duration_ms, scope, target, note), `make_target_profile`/
  `validate_target_profile`, `make_retention_gap`.
- `pattern_db.py`: `audit_path()` (sibling `audit.jsonl` / `$ENGAGEMENT_AUDIT`), `write_audit()`,
  `record()` routes by type, `recall_profile(target)`, `load_profiles()`, emit audit (incl. `denial`
  on skipped/foreign lines) in `main()`, `maybe_gc` call after a pattern append, `audit-stats` subcommand.
- `rotation.py`: `maybe_gc()` (record/byte threshold → lossless `compact()`), `rotate_audit()` writes a
  retention-gap marker before truncating.

### PR2 — Smarter recall: status, decay, BM25, inject
- `schemas.py`: `status`/`confidence`/`last_verified`/`ttl_days`, `STATUS`/`ACTIVE_STATUSES`,
  `rank_score` confidence tie-breaker, `merge` keeps higher-trust status, `pattern_id`.
- `pattern_db.py`: `tokenize`/`bm25_score`/`ALIASES`/`expand_query`, `match(query=…, status=…)`,
  staleness in `merged()`, `inject` subcommand (`--max-bytes`, low-signal sentinel),
  `$ENGAGEMENT_MEMORY_MODE` auto/debug/off, `promote`/`deprecate` verbs.

### PR3 — History, review-gating, scope, secret guard
- `pattern_db.py`: review-gated `record` (`--resolve update|merge|reject|force`), `global_db()` +
  `promote --global` (target/evidence blanked) + `match --include-global`, `history.jsonl` trail.
- `schemas.py`: `rejected_reason`/`merged_into`, secret-input guard in validation.

## Keep / Do-not-copy

Keep: lossless compaction, exact-key dedup, top-N recall, impact ranking, disposable-vs-durable split,
schema_version + fail-fast validation. Do NOT copy: embeddings/vector index, MCP server + runtime hooks,
SSE sync, WebUI/decision-review entity, free-form markdown+YAML records, full per-edit revision history,
ephemeral "working" layer (knowns itself dropped it).
