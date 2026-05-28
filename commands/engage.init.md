---
description: Initialize a new security engagement following the Kill Chain workflow
---

# /engage.init

Initializes a new engagement project with the selected workflow preset.

## Usage

`/engage.init <workflow-type> --client <client-name> [--date YYYY-MM-DD]`

## Workflow Types

- `web-app` — Web application pentest (OWASP-focused)
- `network` — Internal network pentest
- `red-team` — Full red team engagement (all 9 phases)
- `cloud` — Cloud security audit (AWS/Azure/GCP)
- `mobile` — Mobile application pentest (Android/iOS)
- `ad-domain` — Active Directory domain assessment
- `bug-bounty` — Bug bounty hunting

## Process

1. Load the selected workflow YAML from `workflows/<type>.yml`
2. Create engagement directory: `engagement-<client>-<date>/`
3. Create `.engage/state.json` with engagement metadata
4. Copy phase templates from `templates/<phase>/` based on workflow
5. Create `evidence/` subdirectories (screenshots, pcaps, logs)
6. Print status and suggest `/engage.scope` as next step

## State File Structure

The `.engage/state.json` tracks:
- Engagement metadata (client, date, workflow type)
- Current phase (0-8)
- Phase completion status
- Gate validation results
- Findings count per phase

## Next Steps

After initialization, run `/engage.scope` to begin Phase 0 (Scope Definition).
