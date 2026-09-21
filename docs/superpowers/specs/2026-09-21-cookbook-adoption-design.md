# claude-cookbooks Adoption — Design Spec

**Date:** 2026-09-21  **Branch:** `feat/cookbook-adoption`
**Source studied:** [anthropics/claude-cookbooks](https://github.com/anthropics/claude-cookbooks) — Anthropic's own recipes for building with Claude.

## Research verdict (why only two changes)

A deep comparative read (evaluator-optimizer, routing/orchestrator, `building_evals`, `evals/agentic_search`,
contextual-embeddings, prompt_caching, agent-SDK) against the plugin's engine found **most patterns already
implemented, often more safely**, or **API/cloud-coupled** (not applicable to a stdlib/offline/GLM-proxy plugin):

- Evaluator-optimizer → the plugin's blind, bounded, default-to-skeptic `rebuttal.py` is a *stronger* variant
  (the cookbook's is an unbounded `while True:` that auto-accepts on first PASS — a regression for validation). REDUNDANT.
- Routing / orchestrator-workers → the SessionStart dispatcher + `/engage.*` + 8 agents already are this. REDUNDANT.
- Prompt caching / cost optimization → `cache_control` + Anthropic pricing on the first-party API; the GLM proxy
  won't honor it and the safety path is offline. NOT-APPLICABLE. (The plugin already gets the load-bearing half
  right: `judge_protocol.rubric_fingerprint()` is correct cache-key discipline.)
- Agent-SDK / managed-agents / observability → API-hosting examples. NOT-APPLICABLE.

Two things are genuine, offline-clean NET-ADDs:

## A. Labeled held-out eval corpus + code-graded precision/recall  (highest value)

**Gap:** `agent_eval_selftest.py` proves the judge *math* is correct; the only labeled decision set is the 4
planted `judge_protocol.calibration_cases()`. The plugin never measures whether its **deterministic validator**
(`validate_findings.evaluate_finding`, tiers CONFIRMED/POSSIBLE/INFO/REJECTED) actually separates real findings
from bogus ones on a realistic set. Cookbook `building_evals`: prefer **code-based grading**, favor **higher
volume**; `evals/agentic_search`: **hold the grader fixed** so scores are comparable.

**Design:**
- `scripts/ci/eval_corpus/corpus.json` — ~30 labeled finding records, each `{finding..., expected_tier}`,
  spanning the class × (confirm / refuse / disqualify) matrix: SSRF internal-response-read vs status-only;
  IDOR cross-identity vs self_idor; RCE command-output vs blind; XSS script_executed vs encoded_inert; open-redirect
  external vs same_origin; CORS creds-reflected vs not; native memory with/without reachability; ungrounded →
  REJECTED; provenance-cap (non-EXTRACTED hop) CONFIRMED→POSSIBLE; INFO severity; hedge-lint.
- `scripts/ci/eval_corpus.py` — runs `evaluate_finding` over the corpus (offline, deterministic), prints a
  confusion matrix + **per-tier precision/recall/F1** + accuracy. **Fail-closed gate:** (1) ZERO false-CONFIRM
  (any case expected POSSIBLE/INFO/REJECTED but predicted CONFIRMED = hard fail — the dangerous error), and
  (2) exact-match == 100% on the frozen corpus (a labeled regression guard). Exit 0/1/2.
- `tests/scripts/ci/test_eval_corpus.py` sibling; wire into the `consistency` CI job.
- **grader attribution (proportionate):** add `grader_model` to `judge_protocol` as a *recognized, validated-if-
  present* verdict field (validate_verdict_record: if present it must be a non-empty string) + document the
  hold-grader-fixed discipline in `agents/finding-validator.md`. NOT made hard-required — that would break the
  frozen self-test golden + unit tests + doc contracts for a dimension the `model_scorecard` already keys cells by.

## B. Contextual BM25 — a generated situating line per record  (offline half of contextual retrieval)

**Cookbook:** prepend a short generated context to each chunk before indexing; "the same context can be used with
**BM25**" (the half needing no cloud embeddings). Measured Pass@10: 87→92% (embeddings) with contextual-BM25 additive.

**Design (back-compat, no schema migration, no embeddings):**
- `engine/finding_store.py` `add_finding`: accept an optional `finding["context"]`; sanitize it (same private/secret
  redaction) and **prepend `Context: <line>\n\n` to `body`** before store — it flows into the FTS5 mirror via the
  existing triggers, so `search()` matches on the situating context too. No new column.
- `skills/engagement-memory/scripts/pattern_db.py` `doc_tokens`: include `rec.get("context","")` in the token
  stream (complements the existing `ALIASES` expansion). `schemas.make_pattern`: optional `context` param, stored,
  and secret-scrubbed (added to the `evidence_ref/source/technique` looks_like_secret gate).
- Both are back-compat: records without `context` behave exactly as before.

## Quality bar & verification
Every new script gets a tests sibling; findings language unchanged. Re-pin `skills-lock.json` (pattern_db/schemas
under skills/). Run full pytest + 6→7 consistency gates + byte-compile + `bash -n` + `claude plugin validate`.

## Honest deviations
- The eval corpus grades the **deterministic validator** (offline), not the live LLM judge (model-coupled, can't run
  in CI). This is the correct code-graded analogue and is what the cookbook actually recommends prioritizing.
- `grader_model` is recognized-optional, not hard-required (see A) — proportionate to avoid destabilizing a stable protocol.
- The embeddings/rerank/Voyage/Elasticsearch half of contextual retrieval is deliberately NOT adopted (cloud-coupled).
