# Offensive Spec-Driven Development Framework

**Date:** 2026-05-28
**Status:** Approved
**Author:** hypnguyen1209 + AI

---

## 1. Overview

Transform offensive-claude from a flat skill/agent collection into a **Spec-Driven Offensive Security Framework** — applying Spec-Driven Development methodology (inspired by GitHub's spec-kit) to penetration testing and red team engagements.

**Core idea:** Engagements follow the Cyber Kill Chain as a structured pipeline. Each phase has templates, quality gates, skill mappings, and agent coordination — producing consistent, auditable, professional output.

## 2. Kill Chain Pipeline

Classic Lockheed Martin Kill Chain (7 phases) + Phase 0 (Scope) + Phase 8 (Reporting):

```
Phase 0    Phase 1    Phase 2      Phase 3     Phase 4       Phase 5       Phase 6    Phase 7       Phase 8
SCOPE  →  RECON  →  WEAPONIZE →  DELIVERY →  EXPLOIT  →  INSTALLATION →   C2    →  ACTIONS ON →  REPORT
                                                                                    OBJECTIVES
```

### Phase Definitions

| Phase | Kill Chain | ATT&CK Tactic | Input | Output | Gate |
|-------|-----------|----------------|-------|--------|------|
| 0. Scope | — | — | Client request | ROE, targets, boundaries | Authorization confirmed |
| 1. Recon | Reconnaissance | TA0043 | Targets | Attack surface map, vulns | ≥1 target enumerated |
| 2. Weaponize | Weaponization | TA0042 | Vuln list | Payloads, PoCs | Payload ready |
| 3. Delivery | Delivery | TA0001 | Payload | Delivery executed | Vector confirmed |
| 4. Exploit | Exploitation | TA0002 | Delivery success | Access gained | ≥1 finding with evidence |
| 5. Install | Installation | TA0003 | Foothold | Persistence | Persistence documented |
| 6. C2 | Command & Control | TA0011 | Persistence | C2 channel | Channel established |
| 7. Actions | Actions on Objectives | TA0009, TA0010 | C2 access | Data, objectives | Objectives evaluated |
| 8. Report | — | — | All findings | Reports | All findings documented |

### Quality Gates

Each phase transition requires gate validation:

1. Check required artifacts exist (templates filled)
2. Validate mandatory fields per finding (CWE, CVSS, evidence, ATT&CK ID)
3. If FAIL → list missing items, suggest skill to fill gap
4. If PASS → auto-suggest next phase + relevant skills

## 3. Template System

### Directory Structure

```
templates/
├── scope/
│   ├── scope-definition.md
│   └── emergency-contact.md
├── recon/
│   ├── recon-plan.md
│   └── attack-surface.md
├── weaponize/
│   ├── exploit-blueprint.md
│   └── payload-config.md
├── delivery/
│   ├── delivery-plan.md
│   └── social-engineering.md
├── exploit/
│   ├── exploit-plan.md
│   └── findings/
│       └── finding-record.md
├── install/
│   ├── persistence-mechanism.md
│   └── cleanup-plan.md
├── c2/
│   ├── c2-infrastructure.md
│   └── opsec-checklist.md
├── actions/
│   ├── collection-plan.md
│   └── objectives.md
└── report/
    ├── technical-report.md
    ├── executive-summary.md
    └── finding-record.md
```

### Template Format

Each template uses YAML frontmatter for machine-readability:

```yaml
---
phase: exploit
status: draft | active | completed | blocked
gate: required_fields_present
depends_on: [scope/scope-definition.md]
produces: [finding-record.md]
---
```

### Finding Record (Core Output)

```markdown
---
id: FIND-001
phase: exploit
status: confirmed
---

## Finding: [Title]

| Field | Value |
|-------|-------|
| CWE | CWE-XXX |
| CVSS | X.X (vector string) |
| ATT&CK | TXXXX |
| Severity | Critical/High/Medium/Low |
| Target | URL/IP/component |

### Description
[What the vulnerability is]

### Exploitation Path
[Step-by-step exploitation]

### Evidence
- Screenshot: ./evidence/screenshots/XXX.png
- Payload: [exact payload used]
- Tool output: [reference to raw output]

### Impact
[Business impact assessment]

### Remediation
[Specific fix recommendation]
```

## 4. Workflow Engine

### Workflow Definitions

YAML files defining engagement types:

```
workflows/
├── WORKFLOW-ENGINE.md
├── web-app-pentest.yml
├── network-pentest.yml
├── red-team-engagement.yml
├── cloud-security-audit.yml
├── mobile-pentest.yml
└── ad-domain-assessment.yml
```

### Workflow Schema

```yaml
id: <workflow-id>
name: <display name>
kill_chain: classic
phases:
  <phase_name>:
    skills: [skill-1, skill-2]
    agents: [agent-1]
    templates: [template-path-1, template-path-2]
    tools: [tool-1, tool-2]
    gate:
      required: [field_1, field_2]
      min_findings: N
      each_finding: [cwe_id, cvss_score, evidence]
      validation: "<expression>"
    next: <next_phase>
```

### Orchestration Commands

| Command | Phase | Action |
|---------|-------|--------|
| `/engage.init <workflow>` | — | Load workflow, create project structure |
| `/engage.scope` | 0 | Fill scope template, validate authorization |
| `/engage.recon` | 1 | Execute recon skills, populate attack surface |
| `/engage.weaponize` | 2 | Select exploits, design payloads |
| `/engage.deliver` | 3 | Plan/execute delivery vector |
| `/engage.exploit` | 4 | Run exploits, record findings |
| `/engage.install` | 5 | Establish persistence |
| `/engage.c2` | 6 | Setup/document C2 |
| `/engage.actions` | 7 | Execute objectives |
| `/engage.report` | 8 | Generate reports from findings |
| `/engage.status` | — | Show pipeline status, gate results |
| `/engage.gate` | — | Run gate validation on current phase |

## 5. Skill Graph & Dependencies

### Skill Metadata Extension

Each skill gains new frontmatter fields:

```yaml
---
name: <skill-name>
phase: [phase1, phase2]
kill_chain_step: [N, M]
attck_tactics: [TAXXXX]
depends_on: [skill-a, skill-b]
feeds_into: [skill-c, skill-d]
inputs:
  - artifact_name
outputs:
  - artifact_name
---
```

### Dependency Graph

```
recon-osint ──────┬──→ vulnerability-analysis ──→ exploit-development
                  ├──→ web-pentest ──────────────────────┤
                  └──→ network-attack ──→ active-directory-attack
                                              │
                     ┌──────────────────── privesc-linux/windows
                     ↓                         │
               edr-evasion                     ↓
                     │                  advanced-redteam
                     ↓                         │
               shellcode-dev            red-team-ops ──→ threat-hunting
                     │                                     │
               initial-access                    incident-response
```

### Skill-to-Phase Mapping

| Skill | Kill Chain Phases |
|-------|-------------------|
| recon-osint | 1 (Recon) |
| vulnerability-analysis | 1 (Recon), 4 (Exploit) |
| exploit-development | 2 (Weaponize), 4 (Exploit) |
| web-pentest | 3 (Delivery), 4 (Exploit) |
| network-attack | 1 (Recon), 7 (Actions) |
| red-team-ops | 5 (Install), 7 (Actions) |
| cloud-security | 1 (Recon), 4 (Exploit) |
| malware-analysis | 2 (Weaponize) |
| ai-security | 1 (Recon), 4 (Exploit) |
| threat-hunting | 8 (Report) |
| privesc-linux | 4 (Exploit), 7 (Actions) |
| privesc-windows | 4 (Exploit), 7 (Actions) |
| coding-mastery | 2 (Weaponize) |
| crypto-analysis | 1 (Recon), 4 (Exploit) |
| incident-response | 8 (Report) |
| edr-evasion | 3 (Delivery), 5 (Install) |
| initial-access | 3 (Delivery) |
| shellcode-dev | 2 (Weaponize) |
| windows-mitigations | 4 (Exploit) |
| windows-boundaries | 4 (Exploit), 5 (Install) |
| keylogger-arch | 5 (Install), 7 (Actions) |
| mobile-pentest | 1 (Recon), 4 (Exploit) |
| advanced-redteam | 6 (C2), 7 (Actions) |
| active-directory-attack | 4 (Exploit), 7 (Actions) |

## 6. Agent Collaboration Model

### Agent Layers

| Layer | Agent | Role |
|-------|-------|------|
| Planning | redteam-planner | Attack path design, OPSEC strategy, phase coordination |
| Execution | exploit-researcher | CVE research, PoC development, chain building |
| Execution | reverse-engineer | Binary analysis, firmware RE, custom payloads |
| Execution | ai-researcher | AI/ML target assessment, adversarial attacks |
| Analysis | security-reviewer | Finding validation, gate checks, evidence review |
| Analysis | network-analyst | Network mapping, traffic analysis, C2 review |

### Agent-to-Phase Mapping

| Agent | Active Phases |
|-------|---------------|
| redteam-planner | 0 (Scope), 1 (Recon), 2 (Weaponize), 7 (Actions) |
| exploit-researcher | 1 (Recon), 2 (Weaponize), 4 (Exploit) |
| reverse-engineer | 2 (Weaponize), 4 (Exploit), 5 (Install) |
| ai-researcher | 1 (Recon), 2 (Weaponize), 4 (Exploit) |
| security-reviewer | 1 (Recon), 4 (Exploit), 8 (Report) |
| network-analyst | 1 (Recon), 3 (Delivery), 6 (C2), 7 (Actions) |

### Handoff Protocol

```yaml
handoff:
  from: <agent-name>
  to: <agent-name>
  phase: <current-phase>
  type: <finding_validation | exploit_request | opsec_review | intel_share>
  payload:
    finding_id: FIND-XXX
    title: "<description>"
    artifacts: [<file paths>]
    action_required: "<what the receiving agent should do>"
```

### Agent Metadata Extension

```yaml
---
name: <agent-name>
model: opus
layer: planning | execution | analysis
phases: [phase1, phase2]
attck_tactics: [TAXXXX]
receives_from: [agent-a, agent-b]
sends_to: [agent-c, agent-d]
input_artifacts:
  - artifact_name
output_artifacts:
  - artifact_name
---
```

## 7. Preset System

### Available Presets

| Preset | Phases Used | Primary Skills | Use Case |
|--------|-------------|----------------|----------|
| web-app | 0,1,2,4,8 | web-pentest, exploit-dev, recon | OWASP assessment |
| network | 0,1,2,4,5,7,8 | network-attack, privesc-*, recon | Internal network |
| red-team | ALL (0-8) | All 25 skills | Full adversary simulation |
| cloud | 0,1,2,4,8 | cloud-security, recon | AWS/Azure/GCP audit |
| mobile | 0,1,4,8 | mobile-pentest, reverse-eng | Android/iOS testing |
| ad-domain | 0,1,4,5,7,8 | AD-attack, network, privesc | Domain assessment |
| bug-bounty | 0,1,4,8 | web-pentest, recon, exploit-dev | Bug bounty hunting |

### Preset Schema

```yaml
id: <preset-id>
name: <display name>
description: <one-line description>
phases:
  skip: [phase1, phase2]
  required: [phase3, phase4]
skills:
  primary: [skill-1, skill-2]
  secondary: [skill-3]
  exclude: [skill-4]
agents:
  required: [agent-1]
  optional: [agent-2]
templates:
  override:
    <default-path>: <preset-path>
gate_overrides:
  <phase>:
    required: [field1, field2]
    each_finding: [field1, field2]
```

## 8. Engagement Project Structure

When `/engage.init <workflow>` runs, creates:

```
engagement-<client>-<date>/
├── .engage/
│   ├── workflow.yml
│   ├── state.json
│   ├── findings.json
│   └── evidence-index.json
├── scope/
├── recon/
│   └── raw/
├── weaponize/
├── delivery/
├── exploit/
│   └── findings/
├── install/
├── c2/
├── actions/
├── evidence/
│   ├── screenshots/
│   ├── pcaps/
│   └── logs/
└── report/
    └── appendices/
```

### State Tracking (.engage/state.json)

```json
{
  "engagement_id": "acme-2026-05-28",
  "workflow": "web-app-pentest",
  "preset": "web-app",
  "started": "2026-05-28T00:00:00Z",
  "current_phase": "exploit",
  "phases": {
    "scope": {"status": "completed", "gate": "passed"},
    "recon": {"status": "completed", "gate": "passed"},
    "weaponize": {"status": "completed", "gate": "passed"},
    "exploit": {"status": "active", "gate": "pending"},
    "report": {"status": "pending", "gate": "pending"}
  },
  "findings_count": 3,
  "agents_active": ["exploit-researcher", "security-reviewer"]
}
```

## 9. Implementation Plan

### Phase 1: Core Infrastructure
1. Create `templates/` directory with all phase templates
2. Create `workflows/` directory with WORKFLOW-ENGINE.md and YAML definitions
3. Create `commands/` directory with orchestration slash commands
4. Create `presets/` directory with 7 preset configurations

### Phase 2: Skill & Agent Updates
5. Update all 25 skill SKILL.md files with new metadata (phase, depends_on, feeds_into, inputs, outputs)
6. Update all 6 agent .md files with collaboration metadata (layer, phases, receives_from, sends_to)

### Phase 3: Orchestration
7. Write WORKFLOW-ENGINE.md — instructions for Claude Code to execute workflows
8. Write each `/engage.*` command file
9. Update CLAUDE.md with workflow-aware system prompt

### Phase 4: Documentation
10. Update README.md with new structure and usage
11. Update install.sh for new directories
12. Write CHANGELOG

## 10. Success Criteria

- [ ] All 9 phases have complete templates
- [ ] All 25 skills have updated metadata with Kill Chain mapping
- [ ] All 6 agents have collaboration metadata
- [ ] 7 workflow definitions (one per engagement type)
- [ ] 7 presets with appropriate phase/skill/agent selection
- [ ] 12 orchestration commands functional
- [ ] Quality gates validate phase transitions
- [ ] `/engage.status` shows accurate pipeline state
- [ ] README documents full workflow
- [ ] install.sh handles new directory structure
