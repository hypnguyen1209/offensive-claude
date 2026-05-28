---
description: Execute Phase 8 - Final Reporting and Engagement Closeout
---

# /engage.report

Executes Phase 8 (Reporting) of the engagement workflow.

## Usage

`/engage.report [--format <format>] [--severity-threshold <level>]`

Options:
- `--format`: Report format (full, executive, technical)
- `--severity-threshold`: Minimum severity to include (critical, high, medium, low)

## Process

### 1. Finding Aggregation
Gathers all finding records from `exploit/findings/`:
- Reads each `finding-<id>.md` file
- Validates all required fields present
- Sorts findings by severity (Critical > High > Medium > Low)
- Assigns risk ratings using CVSS v3.1 scoring

### 2. Load Report Template
Loads `report/technical-report.md` template with sections:
- Executive Summary
- Engagement Overview
- Methodology
- Finding Summary
- Detailed Findings
- Attack Narrative
- Risk Matrix
- Remediation Roadmap
- Appendices

### 3. Report Population

**Executive Summary** (`report/executive-summary.md`):
- Engagement purpose and scope (1-2 sentences)
- Overall risk posture assessment
- Critical finding count and themes
- Key recommendations (top 3-5)
- Written for non-technical stakeholders

**Engagement Overview**:
- Client and engagement dates
- Scope and methodology
- Tools and techniques used
- Team members (if applicable)

**Finding Summary Table**:
```markdown
| # | Finding | Severity | CWE | CVSS | Status |
|---|---------|----------|-----|------|--------|
| 1 | Nginx RCE | Critical | CWE-120 | 9.8 | Confirmed |
| 2 | Hard-coded Creds | Critical | CWE-798 | 9.1 | Confirmed |
| ... | ... | ... | ... | ... | ... |
```

**Detailed Findings**:
For each finding:
- Title and severity
- Description and technical details
- Exploitation procedure (step-by-step)
- Evidence (screenshots, command output)
- Business impact
- Remediation guidance (specific, actionable)
- References (CVE, CWE, vendor advisory)

**Attack Narrative**:
- Chronological story of the engagement
- How initial access was achieved
- Pivots and lateral movement path
- How objectives were achieved
- Attack path diagram

**Risk Matrix**:
- Findings plotted by likelihood vs. impact
- Overall risk rating
- Comparison to industry benchmarks (if available)

**Remediation Roadmap**:
- Prioritized remediation steps
- Quick wins (immediate, low effort)
- Short-term fixes (1-4 weeks)
- Long-term improvements (1-6 months)
- Strategic recommendations

### 4. Report Validation
Checks:
- All findings from all phases are included
- No placeholder text remains
- Evidence references are valid
- CVSS scores are calculated
- Remediation provided for every finding
- Executive summary is concise and clear

### 5. Deliverable Generation
Creates:
- `report/technical-report.md` — Full technical report
- `report/executive-summary.md` — Executive summary (1-2 pages)
- `report/finding-matrix.md` — Finding summary table
- `report/remediation-roadmap.md` — Prioritized fix list
- `report/attack-narrative.md` — Engagement timeline and story

### 6. Cleanup Verification
Prompts for post-engagement cleanup:
- Were all persistence mechanisms removed? (reference `install/cleanup-plan.md`)
- Were all tools and payloads removed from target?
- Were all test accounts deleted?
- Were all data samples destroyed?
- Were C2 infrastructure servers decommissioned?

### 7. Gate Check
Validates:
- All findings documented in report
- Executive summary present
- Remediation guidance for every finding
- CVSS scores assigned
- Evidence attached
- Cleanup confirmed

### 8. Completion Summary
Prints final engagement summary.

## Example Output

```
Starting Phase 8: Reporting

[1/6] Aggregating Findings
→ Scanning exploit/findings/...
  Found 6 finding records
  Validating required fields...
  ✓ All findings have complete fields

Finding Summary:
  Critical: 3
  High:     2
  Medium:   1
  Low:      0
  Total:    6

[2/6] Loading Report Template
→ Loading report/technical-report.md...
  Template loaded successfully

[3/6] Populating Report

→ Executive Summary...
  ACME Corporation engaged our team for a web application and
  internal network penetration test. The assessment revealed
  3 critical and 2 high severity vulnerabilities that allow
  an external attacker to achieve full domain compromise
  starting from a single exposed web application.

→ Finding Summary Table...
  | # | Finding | Severity | CWE | CVSS |
  |---|---------|----------|-----|------|
  | 1 | Nginx Buffer Overflow RCE | Critical | CWE-120 | 9.8 |
  | 2 | Sensitive Data Exposure | High | CWE-200 | 7.5 |
  | 3 | Sudo Heap Overflow Privesc | High | CWE-122 | 7.8 |
  | 4 | Hard-coded DB Credentials | Critical | CWE-798 | 9.1 |
  | 5 | Domain Admin via Kerberoast | Critical | CWE-916 | 9.0 |
  | 6 | Sensitive File Share Access | Medium | CWE-732 | 6.5 |

→ Detailed Findings (6 findings)...
  Each finding populated with evidence and remediation

→ Attack Narrative...
  Timeline: 2026-05-28 to 2026-05-30
  Attack path: Web RCE → Privesc → DB Access → Kerberoast → DA

→ Remediation Roadmap...
  Immediate: Patch Nginx, rotate DB credentials
  Short-term: Fix sudo, review file share permissions
  Long-term: Implement network segmentation, deploy EDR

[4/6] Validating Report
✓ All 6 findings included
✓ No placeholder text found
✓ All evidence references valid
✓ CVSS scores assigned
✓ Remediation provided for all findings
✓ Executive summary complete

[5/6] Generating Deliverables
→ report/technical-report.md (complete)
→ report/executive-summary.md (complete)
→ report/finding-matrix.md (complete)
→ report/remediation-roadmap.md (complete)
→ report/attack-narrative.md (complete)

[6/6] Cleanup Verification
Were all persistence mechanisms removed?
> Yes, per cleanup plan

Were all tools removed from target?
> Yes

Were test accounts deleted?
> N/A

Was collected data destroyed?
> Yes, samples deleted

Was C2 infrastructure decommissioned?
> Yes, servers wiped

Engagement Complete!

Final Summary:
═══════════════════════════════════════════
  Client: ACME Corporation
  Engagement: Web App + Internal Network Pentest
  Duration: 2026-05-28 to 2026-05-30
  Findings: 6 (3 Critical, 2 High, 1 Medium)
  Objectives: 5/5 achieved
  Overall Risk: CRITICAL
  Report: report/technical-report.md
═══════════════════════════════════════════

Engagement workflow complete.
Deliver report/technical-report.md and report/executive-summary.md
to the client contact identified in the scope document.
```

## Available Skills

- `07-incident-response` — Report formatting and evidence handling
- `06-threat-hunting` — MITRE ATT&CK mapping

## Notes

The report is the primary deliverable of the engagement. It should be thorough, accurate, and actionable. Always ensure cleanup is complete before closing the engagement.
