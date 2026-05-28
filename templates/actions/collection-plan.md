---
phase: actions
status: draft
gate: [collection_plan_documented]
depends_on: [actions/objectives.md]
produces: [report/technical-report.md]
---

# Collection Plan

## Data Classification

| Classification | Example | Handling | Storage |
|----------------|---------|----------|---------|
| PII | Names, emails, SSN | Anonymize, minimize | Encrypted |
| Credentials | Passwords, hashes, tokens | Encrypted, limited access | Vault |
| Business data | Financial records, IP | Scope-specific | Engagement dir |
| System data | Configs, logs, network | No restrictions | Engagement dir |

## Collection Sources

| Source | Data Type | Tool | Authorization |
|--------|-----------|------|---------------|
| Database | | SQL client | In-scope |
| File shares | | SMB, network share | In-scope |
| Memory | LSASS, secrets | Mimikatz, comsvcs | In-scope |
| Browser | History, creds | Lazagne, browser dump | Authorized |
| Email | Communications | Mail API, export | Authorized |
| Cloud | Buckets, secrets | Cloud CLI, API | In-scope |

## Storage & Encryption

| Field | Value |
|-------|-------|
| Local storage | ./evidence/ |
| Encryption | AES-256 |
| Key management | |
| Retention after engagement | 90 days / destroy immediately |

## Exfiltration Method

| Method | Detail | Detection Risk |
|--------|--------|---------------|
| | | Low / Med / High |
| Backup | | |

## OPSEC & Cleanup

- [ ] Collected data minimized to scope
- [ ] PII anonymized or excluded
- [ ] All data encrypted at rest
- [ ] Data destroyed after retention period
- [ ] Chain of custody maintained
