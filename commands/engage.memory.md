---
description: Cross-engagement pattern memory — recall prior techniques, record confirmed findings, housekeeping
---

# /engage.memory

Manage the cross-engagement learning store (`skills/engagement-memory`). Patterns are ranked by
impact (CVSS/severity) and recalled as an explicit top-N query.

## Usage

`/engage.memory <recall|record|gc|stats> [options]`

## Subcommands

### recall
Pull the top prior patterns for the current target's class / tech stack and write them to
`.engage/recon/prior-intel.md` so weaponization starts from what already worked.

```bash
python skills/engagement-memory/scripts/pattern_db.py match \
    --vuln-class <class> --tech-stack <a,b> --target <host> --top 10 --json
```

### record
Persist a `[CONFIRMED]` finding (run after `/engage.report` / `validate_findings.py`). Only confirmed
findings are recorded; `[POSSIBLE]`/`[REJECTED]` are not learned.

```bash
python skills/engagement-memory/scripts/pattern_db.py record --json '<finding json>'
```

### gc
Compact the pattern DB (dedup-merge, knowledge preserved) and rotate the disposable audit log.

```bash
python skills/engagement-memory/scripts/pattern_db.py compact
```

### stats
Show pattern counts by vulnerability class.

## Notes

- Storage: `~/.claude/engagement-memory/patterns.jsonl` (override `$ENGAGEMENT_DB`; use a per-client DB
  if ROE requires client isolation).
- Recall is generic-by-class/stack; review before reusing across clients.
- Records hold technique + CWE/CVSS + an evidence *reference*, never raw loot.
