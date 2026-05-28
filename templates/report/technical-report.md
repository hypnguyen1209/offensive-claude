---
phase: report
status: draft
gate: [all_findings_documented, report_generated]
depends_on: [exploit/findings/finding-record.md]
produces: []
---

# Technical Security Assessment Report

## Document Control

| Field | Value |
|-------|-------|
| **Client** | |
| **Engagement ID** | |
| **Date** | |
| **Classification** | CONFIDENTIAL |
| **Lead Tester** | |
| **Team** | |

## Executive Summary

### Background
[1-2 paragraphs describing the engagement scope and objectives]

### Key Findings

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| 1 | | Critical/High/Medium/Low | Confirmed |
| 2 | | | |
| 3 | | | |

### Critical Risk Summary

[1 paragraph on the most critical findings and their business impact]

### Recommendations
1. [Highest priority action]
2. [Second priority action]
3. [Third priority action]

## Engagement Timeline

| Date | Phase | Activity |
|------|-------|----------|
| | | |

## Scope

### In-Scope
[from scope-definition.md]

### Out-of-Scope
[from scope-definition.md]

### Methodology
[OWASP / PTES / OSSTMM / NIST SP 800-115 / Custom]
[Kill Chain phases applied]

## Findings Detail

<!-- One section per finding, generated from finding-record.md -->
### FIND-XXX: [Finding Title]

**Severity:** Critical/High/Medium/Low
**CVSS:** X.X
**CWE:** CWE-XXX
**ATT&CK:** TXXXX

**Description:** [from finding record]

**Affected:** [target and component]

**Proof of Concept:** [steps to reproduce]

**Impact:** [business impact]

**Recommendation:** [remediation]

---

## Risk Summary

| Severity | Count |
|----------|-------|
| Critical | |
| High | |
| Medium | |
| Low | |
| Info | |

## Attack Path Narrative

[Optional: step-by-step narrative of the full attack chain, useful for red team engagements]

1. Initial recon discovered [x] at [target]
2. Exploited [vulnerability] to gain [level of access]
3. Escalated to [privilege level]
4. Moved laterally to [additional systems]
5. Achieved [objective]

## Remediation Priorities

| Priority | Action | Timeframe |
|----------|--------|-----------|
| P1 | | 0-30 days |
| P2 | | 30-90 days |
| P3 | | 90+ days |

## Appendices

### A: Evidence Index

| Finding | Evidence Type | File | Timestamp |
|---------|---------------|------|-----------|
| FIND-001 | Screenshot | | |

### B: Tools Used

| Tool | Version | Purpose |
|------|---------|---------|
| | | |

### C: References

- CWE list
- CVE list
- ATT&CK Navigator link
- Raw tool output (separate file)
