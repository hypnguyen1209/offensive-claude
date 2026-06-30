---
description: Calibrate model verdict trust (Wilson-bounded miss-rate) to short-circuit re-validation
---

# /engage.scorecard

Tracks how often a model's verdicts (finding-validator / finding-checker PASS/KILL/DOWNGRADE) were
later overturned, and decides — fail-closed — when a (model, decision_class) cell is trustworthy
enough to skip an expensive re-validation in the autopilot loop. Backed by `engine/model_scorecard.py`.

## Usage

`/engage.scorecard {record|rate|trusted|stats} ...`

## Process

1. **Record outcomes** as you confirm them:
   `model_scorecard.py record --model opus --class finding-validator:PASS --outcome correct|overturned`
   (a "miss" = a verdict later overturned: a PASS that was a false positive, a KILL that was real).
2. **Consult before skipping a re-check** (autopilot):
   `model_scorecard.py trusted --model opus --class finding-validator:PASS` → exit 0 trusted, 3 not.
   A cell is trusted ONLY when the Wilson 95% **upper** bound on its miss-rate ≤ 5% **and** there are
   enough samples (≈73+ clean) — fail-closed: a new/rarely-seen model or one recent miss is NOT
   trusted, so the autopilot keeps re-validating.
3. **Review** — `model_scorecard.py stats` shows per-(model, class) n / overturned / upper-bound /
   trusted.

## Notes
- Separate sqlite store (`$MODEL_SCORECARD_DB`), distinct from the JSONL engagement-memory pattern store.
- This only ever *adds* a fast-path for well-proven cells; it never relaxes the proof bar — an
  untrusted cell simply gets the normal finding-validator + finding-checker treatment.
