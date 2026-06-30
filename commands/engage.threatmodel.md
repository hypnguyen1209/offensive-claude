---
description: Materialize, lint, and drift-check the engagement threat model
---

# /engage.threatmodel

Builds the threat model from recon-osint output, lints it for completeness, and diffs a re-run
against the reviewed baseline to catch new unreviewed attack surface (drift). Backed by
`skills/threat-model-discipline/` + `scripts/threatmodel_lint.py`; the drift check hooks into
`/engage.gate`.

## Usage

`/engage.threatmodel {materialize|lint|drift} ...`

## Process

1. **Materialize** — from recon-osint output, fill `templates/threat-model/threat-model.md` and its
   machine-readable `threat-model.json` (assets, entry_points, trust_boundaries, attck, mitigations).
2. **Lint** — `threatmodel_lint.py lint .engage/recon/threat-model.json`: every required field
   present, no `TBD`/`[fill in]` placeholders, valid ATT&CK ids. Exit 1 if incomplete.
3. **Baseline** — after review, save `threat-model.baseline.json`.
4. **Drift** — re-run recon → regenerate `threat-model.json` →
   `threatmodel_lint.py drift baseline.json threat-model.json`. A NEW entry point / asset / trust
   boundary is unreviewed surface and **blocks the gate** (exit 1) until re-reviewed or explicitly
   acknowledged. Removed surface is recorded but does not block.

## Notes
- `attck` changes are not surface drift (they're coverage, not new surface) — only
  entry_points/assets/trust_boundaries additions block.
- Pairs with `scope-discipline` (what's in bounds) and `finding-discipline` (what counts as proven).
