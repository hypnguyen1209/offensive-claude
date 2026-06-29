---
name: engagement-memory
description: Use when recalling prior techniques at recon/weaponize, or recording a confirmed finding at report — cross-engagement pattern memory ranked by impact
metadata:
  type: support
  phase: all
  tools: pattern_db.py, schemas.py, rotation.py
kill_chain:
  phase: [recon, weaponize, report]
  step: [1, 2, 8]
  attck_tactics: []
  attck_techniques: []
depends_on: [vulnerability-analysis]
feeds_into: [recon-osint, exploit-development, web-pentest]
inputs: [confirmed_findings, target, tech_stack]
outputs: [prior_intel, ranked_patterns]
references: []
scripts:
  - scripts/pattern_db.py
  - scripts/schemas.py
  - scripts/rotation.py
---

# Engagement Memory (cross-engagement learning)

## When to Activate

- At **recon/weaponize**: recall what already worked against this target class / tech stack.
- At **report**: persist each `[CONFIRMED]` finding as a reusable pattern (ranked by impact).
- Periodic housekeeping: compact the pattern DB / rotate the audit log.

## Model

Append-only JSONL store (`~/.claude/engagement-memory/patterns.jsonl`, override `$ENGAGEMENT_DB`).
A pattern is keyed by `(target, vuln_class, technique)` and ranked by **CVSS / severity** (real
impact — never bug-bounty payout). Recall is an **explicit top-N query**, not "load everything"
(anti-context-bloat). Duplicates are **merged** (count bumped), never blind-discarded; compaction
preserves knowledge.

## Commands

```bash
# RECALL at recon/weaponize — start from what worked (writes .engage/recon/prior-intel.md)
python skills/engagement-memory/scripts/pattern_db.py match --vuln-class ssrf --tech-stack nginx,aws --top 10

# RECORD a confirmed finding at report time (flags or a finding JSON)
python skills/engagement-memory/scripts/pattern_db.py record --target acme.com --vuln-class ssrf \
    --cwe CWE-918 --attack-id T1190 --severity high --cvss 9.1 --tech-stack nginx,aws --technique "metadata theft"
python skills/engagement-memory/scripts/pattern_db.py record --json '<finding json from validate_findings>'

# Housekeeping
python skills/engagement-memory/scripts/pattern_db.py compact      # dedup-merge (patterns preserved)
python skills/engagement-memory/scripts/pattern_db.py stats
```

Or use the `/engage.memory` command (recall | record | gc | stats).

## OPSEC & Detection

| Concern | Note |
|---------|------|
| Sensitive data at rest | The DB stores techniques + CWE/CVSS + an evidence *reference*, not raw loot. Keep `evidence_ref` a path, not the secret. |
| Cross-client bleed | Patterns are keyed by target; recall by class/stack is generic, but review before sharing a DB across clients. Use per-client `$ENGAGEMENT_DB` if isolation is required by ROE. |
| Integrity | Records carry `schema_version`; malformed/foreign lines are skipped on read, not trusted. |

## Deep Dives

- `scripts/schemas.py` — record types, validation, `pattern_key`, impact `rank_score`, `merge`.
- `scripts/pattern_db.py` — append-only store, merge-on-read, ranked top-N `match`, CLI.
- `scripts/rotation.py` — `compact` (dedup-merge, preserve) vs `rotate_audit` (discard disposable log).
