---
description: Show current engagement status and pipeline progress
---

# /engage.status

Displays the current state of the active engagement workflow.

## Usage

`/engage.status`

## Output

Shows:
- **Engagement Info**: Client name, workflow type, start date
- **Current Phase**: Active phase name and number (0-8)
- **Completed Phases**: List of phases that passed gate validation
- **Gate Status**: Current phase gate validation status (pass/fail/pending)
- **Findings Count**: Total findings across all phases
- **Evidence Collected**: Count of screenshots, pcaps, logs
- **Suggested Next Action**: Recommended next command to run

## Phase Status Indicators

- ✓ Phase completed and gate passed
- → Current active phase
- ○ Phase not yet started
- ✗ Phase gate validation failed

## Example Output

```
Engagement: ACME Corp Web Application Pentest
Workflow: web-app
Started: 2026-05-28

Pipeline Status:
✓ Phase 0: Scope Definition
✓ Phase 1: Reconnaissance
→ Phase 2: Weaponization (IN PROGRESS)
○ Phase 3: Delivery
○ Phase 4: Exploitation

Current Phase Gate: PENDING
Findings: 12 total (3 critical, 5 high, 4 medium)
Evidence: 47 screenshots, 8 pcaps, 23 logs

Suggested Next Action: Complete payload configuration, then run /engage.gate
```

## Notes

Run this command frequently to track progress and ensure you're following the workflow sequence.
