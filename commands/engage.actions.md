---
description: Execute Phase 7 - Actions on Objectives and Goal Achievement
---

# /engage.actions

Executes Phase 7 (Actions on Objectives) of the engagement workflow.

## Usage

`/engage.actions [--objective <objective-id>]`

Options:
- `--objective`: Execute a specific objective from the scope document

## Process

### 1. Load Templates
Loads:
- `actions/objectives.md` — Engagement objectives tracker
- `actions/collection-plan.md` — Data collection and handling plan

### 2. Objective Review
Retrieves engagement objectives from Phase 0 scope document:
- Lists all defined objectives
- Identifies which objectives are already achieved (from Phase 4)
- Prioritizes remaining objectives by impact and feasibility
- Determines what additional access or movement is needed

### 3. Objective Execution
For each remaining objective:

**Lateral Movement** (if needed):
- Identify reachable network segments
- Enumerate accessible hosts and services
- Discover credentials or tokens for movement
- Move to target systems via authorized techniques
- Document each pivot point

**Privilege Escalation** (if needed):
- Identify current privilege level on target system
- Enumerate escalation vectors
- Execute escalation technique
- Document pre/post privilege level

**Data Discovery and Collection** (if authorized):
- Locate target data per engagement scope
- Document data locations and access method
- Collect representative samples only (per ROE)
- Handle data per engagement data handling policy
- Never exfiltrate production customer data without explicit authorization

**Domain Dominance** (AD engagements):
- Enumerate Active Directory structure
- Identify domain admin paths
- Execute Kerberos attacks (if authorized)
- Achieve domain admin (if objective)
- Document trust relationships

### 4. Evidence and Documentation
For each objective achieved:

**Objective Record** (`actions/objective-<id>.md`):
```markdown
# Objective: [Title]

**Status**: Achieved / Partially Achieved / Not Achievable
**MITRE ATT&CK**: T1XXX, T1YYY

## Execution Steps
1. [Step-by-step procedure]
2. [...]

## Evidence
- [Screenshot/output references]

## Impact Assessment
[Business impact of achieving this objective]

## Systems Accessed
| Host | IP | User | Access Method |
|------|----|------|---------------|
| ... | ... | ... | ... |
```

### 5. Collection Plan
If data collection is an objective, populates `collection-plan.md`:
- What data was targeted
- What data was accessed (description only, no actual data)
- Data handling procedures followed
- Data destruction plan post-engagement

### 6. Gate Check
Validates:
- All achievable objectives documented
- Each objective has evidence
- Lateral movement documented (if performed)
- Collection plan completed (if applicable)
- All accessed systems recorded

### 7. Next Steps
If gate passes, suggests: `/engage.report`

## Example Output

```
Starting Phase 7: Actions on Objectives

Reviewing engagement objectives from scope...

Objectives:
1. ✓ Achieve remote code execution (completed Phase 4)
2. ✓ Escalate to root privileges (completed Phase 4)
3. ○ Access internal database server
4. ○ Demonstrate domain admin compromise
5. ○ Access sensitive financial documents

Starting from: admin.acme-corp.com (root)
C2: Active, last callback 12s ago

[Objective 3] Access internal database server
→ Enumerating network from admin.acme-corp.com...
  Internal network: 10.0.1.0/24
  Database server found: db01.internal (10.0.1.100)
  Port 3306/tcp (MySQL) open

→ Retrieving database credentials...
  Found in /var/www/html/config/database.php:
  User: app_admin
  Database: acme_production

→ Connecting to database...
  ✓ Connected to db01.internal:3306 as app_admin
  Tables enumerated: 47 tables
  Sample data: Confirmed access to customer records

→ Creating finding record...
  Finding-004: Internal Database Accessible via Stolen Credentials
  Severity: Critical | CWE-798 (Hard-coded Credentials)
  Evidence: evidence/screenshots/finding-004-db-access.png

[Objective 4] Demonstrate domain admin compromise
→ Identifying AD environment...
  Domain: acme.local
  Domain Controller: dc01.acme.local (10.0.1.10)
  Current context: Linux host (non-domain)

→ Discovering AD credentials...
  Found: Kerberos keytab in /etc/krb5.keytab
  Principal: HTTP/admin.acme-corp.com@ACME.LOCAL

→ Executing Kerberoasting...
  Found 3 SPNs with crackable encryption (RC4)
  Cracked: svc_backup (Password123!)

→ Checking svc_backup privileges...
  Member of: Backup Operators, Domain Users
  Backup Operators → DCSync capability

→ Executing DCSync...
  ✓ Retrieved domain admin NTLM hash
  ✓ Domain admin compromise demonstrated

→ Creating finding record...
  Finding-005: Domain Admin via Kerberoasting + DCSync
  Severity: Critical | CWE-916 (Weak Password Hash)
  MITRE ATT&CK: T1558.003, T1003.006

[Objective 5] Access sensitive financial documents
→ Mapping file shares from domain context...
  \\fileserver.acme.local\Finance$ — Access Denied
  \\fileserver.acme.local\Finance — Accessible as svc_backup
  Found: Q1_2026_Financial_Report.xlsx (confirmed access)
  (No data exfiltrated per ROE — screenshot only)

→ Creating finding record...
  Finding-006: Sensitive Financial Data Accessible
  Severity: High | CWE-732 (Incorrect Permission Assignment)

All objectives achieved.

Systems Accessed:
| Host | IP | User | Method |
|------|-----|------|--------|
| admin.acme-corp.com | 10.0.1.42 | root | CVE-2024-1234 + privesc |
| db01.internal | 10.0.1.100 | app_admin | Credential reuse |
| dc01.acme.local | 10.0.1.10 | svc_backup | Kerberoasting |
| fileserver.acme.local | 10.0.1.20 | svc_backup | Domain creds |

Running gate validation...

✓ Phase 7 (Actions on Objectives) gate validation PASSED
All 5 objectives achieved and documented.
6 total findings across engagement.

Ready to proceed to Phase 8 (Reporting).
Run: /engage.report
```

## Available Skills

- `25-active-directory-attack` — AD exploitation, Kerberos, NTLM relay
- `14-red-team-ops` — Lateral movement and post-exploitation
- `10-cloud-security` — Cloud attack paths
- `12-privesc-linux` — Linux privilege escalation
- `13-privesc-windows` — Windows privilege escalation

## Notes

Actions on Objectives is where the engagement delivers real value. Always tie findings back to business impact. Handle any collected data per the ROE and destroy it after the engagement.
