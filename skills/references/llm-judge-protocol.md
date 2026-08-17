# LLM-Judge Protocol

The two judge agents (`finding-validator`, `finding-checker`) and the mechanical validators speak one
shared protocol so their verdicts are reproducible, comparable across runs, and cache-safe. The
protocol is **code, not prose** — its single source of truth is `engine/judge_protocol.py`; this doc
explains it. If the two ever disagree, the code wins.

## 1. Discrete grounding confidence (no free-floating 0-1)

A judge never emits an arbitrary confidence number. Grounding confidence is exactly **one of five
named buckets**; if none fit, the claim is **AMBIGUOUS** and the judge stops rather than inventing a
score. This is the *grounding* axis (how tightly the claim is tied to the artifact) — orthogonal to
the impact tier (`[CONFIRMED]` / `[POSSIBLE]` / `[INFO]`).

| score | label | assign when… |
|------:|-------|--------------|
| 0.95 | CERTAIN | a direct quote from the artifact proves the claim; no inference |
| 0.85 | STRONG | stated in the artifact but needs trivial composition of two direct quotes |
| 0.75 | PROBABLE | rests on an assumption the artifact explicitly supports |
| 0.65 | TENTATIVE | a flagged inference from surrounding code; not directly stated |
| 0.55 | WEAK | plausible but unverified — the weakest defensible claim |
| — | AMBIGUOUS | none of the above hold; do **not** interpolate a number |

`normalize_confidence()` is fail-closed: any off-bucket value (a smuggled `0.90`, `"high"`, `None`)
maps to AMBIGUOUS — it is never snapped to the nearest bucket, so "almost CERTAIN" cannot masquerade
as CERTAIN.

## 2. Formal judge protocol (reproducible + cache-safe)

Every verdict record is produced and stored under these invariants (`validate_verdict_record()`):

- **Pinned decoding.** `temperature=0, top_p=1` (`JUDGE_DECODING`). A verdict produced off these
  settings is not comparable and must not be cached as if it were.
- **Versioned rubric.** The record carries `rubric_version` (currently `1.0.0`). A record whose
  version ≠ the current standard is flagged stale.
- **Mandatory evidence for accepts.** Any accept decision (`PASS` / `ACCEPTED` / `CONFIRMED`) must
  cite ≥1 re-verifiable `[EVD-XXX]` id, grounded in the `evidence_kit.py` store. No citation ⇒ the
  record is non-conformant.
- **Cache invalidation by rubric.** The verdict cache key (`cache_key()`) folds in
  `rubric_fingerprint()` — a content hash of the version + buckets + decoding + rubric text. Bump the
  rubric and **every** stale verdict misses the cache and is re-judged; you never serve a verdict that
  was judged against an old standard.

## 3. Calibration gate (a judge that can't rank is void)

Before trusting a batch of verdicts, the judge is run against planted cases (`calibration_cases()`):
two obvious PASS (grounded + `[EVD-XXX]` cited) and two obvious KILL (unfalsifiable, no evidence).
`is_calibrated(pass_scores, kill_scores)` returns True only if **every** planted-PASS score ranks
**strictly above** every planted-KILL score. Any overlap — even a tie — means the judge cannot
separate real from bogus on this batch, so its verdicts here are **NOT TRUSTWORTHY** and are void.
Empty on either side is also not calibrated (no evidence of separation).

## 4. Where this plugs in

- `finding-validator` / `finding-checker` emit `confidence` from the five buckets (or AMBIGUOUS) and
  `rubric_version` from this protocol; accepts carry `[EVD-XXX]`.
- `scripts/ci/agent_eval_selftest.py` runs the discrete-bucket, cache-key, evidence-contract, and
  calibration checks as frozen golden scenarios — a drift in the rubric or a broken invariant fails CI.
- `engine/model_scorecard.py` records inter-judge agreement (Cohen's kappa) as a reliability signal
  alongside miss-rate; low kappa means the accept/reject signal itself is noisy.
