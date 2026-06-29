# Workflow Engine Documentation

## Overview

The Workflow Engine orchestrates multi-phase security engagements following the Classic Cyber Kill Chain methodology. It coordinates skills, agents, templates, and tools across 9 distinct phases, ensuring systematic progression with validation gates between each phase.

## Architecture

### Kill Chain Phases

The Classic Cyber Kill Chain consists of 9 phases:

| Phase | ID | Purpose | Typical Duration |
|-------|----|---------|--------------------|
| **Scope** | 0 | Define targets, authorization, ROE | 1-2 days |
| **Recon** | 1 | Passive/active reconnaissance, OSINT | 2-5 days |
| **Weaponize** | 2 | Exploit selection, payload development | 1-3 days |
| **Delivery** | 3 | Initial access vector execution | 1-2 days |
| **Exploit** | 4 | Vulnerability exploitation, findings | 3-7 days |
| **Install** | 5 | Persistence mechanism deployment | 1-2 days |
| **C2** | 6 | Command & control infrastructure | 1-2 days |
| **Actions** | 7 | Objective execution, lateral movement | 2-5 days |
| **Report** | 8 | Documentation, findings, remediation | 2-3 days |

Not all engagement types require all phases. See workflow definitions for phase selection per engagement type.

## Workflow YAML Format

### Schema

```yaml
id: workflow-identifier
name: Human-Readable Workflow Name
kill_chain: classic
phases:
  phase_name:
    skills: [skill-1, skill-2]
    agents: [agent-1, agent-2]
    templates: [path/to/template.md]
    tools: [tool1, tool2]  # optional
    gate:
      required: [artifact_1, artifact_2]
      min_findings: N  # optional, for exploit phase
      validation: custom_check  # optional
      each_finding: [field_1, field_2]  # optional, for exploit phase
    next: next_phase_name  # omit for final phase
```

### Field Definitions

**Top Level:**
- `id`: Unique workflow identifier (kebab-case)
- `name`: Display name for the workflow
- `kill_chain`: Always "classic" for now (future: custom chains)

**Phase Level:**
- `skills`: Array of skill IDs to load (from `skills/` directory)
- `agents`: Array of agent IDs available for delegation (from `agents/` directory)
- `templates`: Array of template paths relative to `templates/` directory
- `tools`: Optional array of external tools required (nmap, nuclei, etc.)
- `gate`: Validation requirements before proceeding to next phase
- `next`: ID of the next phase (omit for final phase)

**Gate Level:**
- `required`: Array of artifact names that must exist in `.engage/` directory
- `min_findings`: Minimum number of findings required (exploit phase)
- `validation`: Custom validation function name (advanced)
- `each_finding`: Array of required fields in each finding record

## Execution Protocol

### Starting an Engagement

Command: `/engage <workflow-id>`

Example: `/engage web-app-pentest`

**Execution Steps:**

1. Load workflow YAML from `workflows/<workflow-id>.yml`
2. Create `.engage/` directory structure
3. Initialize state file `.engage/state.json`
4. Load phase 0 (scope) templates
5. Present templates to user for completion
6. Wait for user to fill templates

### State File Format

`.engage/state.json`:

```json
{
  "workflow_id": "web-app-pentest",
  "workflow_name": "Web Application Penetration Test",
  "current_phase": "recon",
  "phase_history": ["scope", "recon"],
  "started_at": "2026-05-28T10:00:00Z",
  "updated_at": "2026-05-28T14:30:00Z",
  "artifacts": {
    "scope/scope-definition.md": {
      "created_at": "2026-05-28T10:15:00Z",
      "status": "complete",
      "gate_validated": true
    },
    "recon/recon-plan.md": {
      "created_at": "2026-05-28T12:00:00Z",
      "status": "in_progress",
      "gate_validated": false
    }
  },
  "findings": [
    {
      "id": "FIND-001",
      "title": "SQL Injection in login endpoint",
      "severity": "critical",
      "cwe": "CWE-89",
      "cvss": 9.8,
      "status": "confirmed",
      "file": "exploit/findings/FIND-001.md"
    }
  ],
  "gate_status": {
    "scope": "passed",
    "recon": "in_progress"
  }
}
```

### Phase Transition Protocol

**Before transitioning to the next phase:**

1. **Load current phase gate requirements** from workflow YAML
2. **Validate all required artifacts exist** in `.engage/` directory
3. **Check artifact completeness:**
   - Templates have frontmatter `status: complete`
   - Required fields are filled (not empty)
   - Checklists are checked where applicable
4. **Phase-specific validation:**
   - **Scope:** Authorization confirmed, targets defined, ROE signed
   - **Recon:** Minimum data collected, attack surface documented
   - **Exploit:** At least one finding with complete fields (CWE, CVSS, ATT&CK, PoC)
   - **Report:** All findings documented, report generated
5. **Update state file** with gate validation results
6. **If gate passes:** Load next phase templates and skills
7. **If gate fails:** Report missing artifacts/fields to user

### Gate Check Implementation

```python
def validate_gate(phase_name, gate_config, engage_dir):
    """
    Validate phase gate requirements.
    
    Returns: (passed: bool, missing: list, errors: list)
    """
    missing = []
    errors = []
    
    # Check required artifacts
    for artifact in gate_config.get('required', []):
        artifact_path = engage_dir / artifact
        if not artifact_path.exists():
            missing.append(artifact)
            continue
        
        # Parse frontmatter
        frontmatter = parse_frontmatter(artifact_path)
        if frontmatter.get('status') != 'complete':
            errors.append(f"{artifact}: status not 'complete'")
    
    # Check minimum findings (exploit phase)
    if 'min_findings' in gate_config:
        findings = load_findings(engage_dir / 'exploit/findings')
        if len(findings) < gate_config['min_findings']:
            errors.append(f"Need {gate_config['min_findings']} findings, have {len(findings)}")
        
        # Validate each finding has required fields
        if 'each_finding' in gate_config:
            for finding in findings:
                for field in gate_config['each_finding']:
                    if not finding.get(field):
                        errors.append(f"{finding['id']}: missing {field}")
    
    passed = len(missing) == 0 and len(errors) == 0
    return passed, missing, errors
```

## Template Filling Flow

### Phase Start

1. **Load phase definition** from workflow YAML
2. **Copy templates** from `templates/<phase>/` to `.engage/<phase>/`
3. **Present templates to user** with instructions
4. **Load relevant skills** specified in phase config
5. **Activate agents** specified in phase config

### User Interaction

User fills templates by:
- Editing files directly in `.engage/` directory
- Asking Claude to fill specific sections
- Running skills to generate data (e.g., `/skill recon-osint` → populate attack-surface.md)

### Template Frontmatter

Every template has YAML frontmatter:

```yaml
---
phase: recon
status: draft  # draft | in_progress | complete
gate: [targets_confirmed, tools_selected]
depends_on: [scope/scope-definition.md]
produces: [recon/attack-surface.md]
---
```

**Status values:**
- `draft`: Template copied, not started
- `in_progress`: User is filling the template
- `complete`: Template filled, ready for gate validation

### Artifact Generation

Skills and agents generate artifacts:

```bash
# Example: recon skill generates subdomain list
/skill recon-osint --target example.com
# → Creates .engage/recon/subdomains.txt
# → Updates .engage/recon/attack-surface.md
```

## Agent Coordination

### Handoff Protocol

Agents coordinate through the `.engage/` directory:

1. **Agent A** completes task, writes artifact
2. **Agent A** updates artifact frontmatter: `status: complete`
3. **Agent A** updates state.json with completion
4. **Agent B** reads artifact, begins dependent task
5. **Agent B** references Agent A's work in `depends_on` field

### Agent Communication

Agents communicate via:
- **Artifacts:** Primary communication mechanism
- **State file:** Coordination and status tracking
- **Frontmatter:** Dependency and status signaling

Example handoff:

```markdown
# recon-plan.md (by redteam-planner)
---
phase: recon
status: complete
produces: [recon/attack-surface.md]
---
[recon plan content]
```

```markdown
# attack-surface.md (by network-analyst)
---
phase: recon
status: complete
depends_on: [recon/recon-plan.md]
---
[attack surface content based on recon plan]
```

## Skill Loading

### Automatic Skill Loading

When entering a phase, Claude Code automatically:

1. Reads phase `skills` array from workflow YAML
2. Loads each skill's `SKILL.md` file from `skills/<skill-id>/SKILL.md`
3. Makes skill context available to Claude
4. Enables skill-specific commands

### Skill Invocation

```bash
# Direct skill invocation
/skill recon-osint --target example.com

# Skill with specific task
/skill exploit-development --cve CVE-2024-1234

# Skill with agent delegation
/agent exploit-researcher --task "develop PoC for FIND-001"
```

## Tool Integration

### External Tools

Phases can specify required external tools:

```yaml
recon:
  tools: [subfinder, httpx, nuclei, katana, ffuf, nmap]
```

**Tool check on phase start:**

```bash
# Claude checks tool availability
which subfinder || echo "Install: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
```

### Tool Output Integration

Tools write output to `.engage/<phase>/tool-output/`:

```bash
# Example: nmap scan
nmap -sV -oA .engage/recon/tool-output/nmap_scan target.com

# Claude parses output and updates attack-surface.md
```

## Workflow Types

### Full Kill Chain (Red Team)

All 9 phases: scope → recon → weaponize → delivery → exploit → install → c2 → actions → report

**Use case:** Full adversary simulation, APT emulation

### Abbreviated Chains

**Web App Pentest:** scope → recon → weaponize → delivery → exploit → report
- Skip: install, c2, actions (no persistence needed)

**Bug Bounty:** scope → recon → exploit → report
- Skip: weaponize, delivery, install, c2, actions (lightweight, no persistence)

**Cloud Audit:** scope → recon → exploit → report
- Skip: weaponize, delivery, install, c2, actions (configuration review focus)

**Network Pentest:** scope → recon → weaponize → exploit → install → c2 → actions → report
- Skip: delivery (internal network, no initial access needed)

## Commands

### Engagement Commands

```bash
# Start new engagement
/engage <workflow-id>

# Resume engagement
/engage resume

# Check current phase status
/engage status

# Validate current gate
/engage validate

# Force phase transition (skip gate)
/engage next --force

# List available workflows
/engage list

# Show workflow details
/engage show <workflow-id>
```

### Phase Commands

```bash
# Complete current artifact
/phase complete <artifact-name>

# List phase artifacts
/phase artifacts

# Show phase gate requirements
/phase gate

# Transition to next phase
/phase next
```

### Finding Commands

```bash
# Create new finding
/finding new --title "SQL Injection" --severity critical

# List findings
/finding list

# Update finding
/finding update FIND-001 --status confirmed

# Export findings
/finding export --format json
```

## Best Practices

### Template Completion

1. **Fill templates incrementally** as information becomes available
2. **Update status** in frontmatter as you progress
3. **Reference dependencies** in `depends_on` field
4. **Mark complete** only when all required fields are filled

### Gate Validation

1. **Check gate requirements** before starting phase work
2. **Validate early and often** with `/engage validate`
3. **Don't force-skip gates** unless absolutely necessary
4. **Document reasons** if skipping validation

### Agent Delegation

1. **Use agents for specialized tasks** (exploit research, binary analysis)
2. **Provide clear context** in delegation request
3. **Review agent output** before marking artifacts complete
4. **Maintain handoff protocol** for multi-agent workflows

### Finding Documentation

1. **Create finding records immediately** upon discovery
2. **Include all required fields:** CWE, CVSS, ATT&CK, PoC, evidence
3. **Validate exploitability** before marking confirmed
4. **Cross-reference** findings in exploit plan and report

## Troubleshooting

### Gate Validation Fails

**Problem:** Gate validation fails, can't proceed to next phase

**Solution:**
1. Run `/engage validate` to see missing artifacts
2. Check artifact frontmatter status
3. Fill missing required fields
4. Update status to `complete`
5. Re-run validation

### Missing Dependencies

**Problem:** Agent can't find required artifact from previous phase

**Solution:**
1. Check `depends_on` field in template frontmatter
2. Verify dependency artifact exists in `.engage/` directory
3. Ensure dependency status is `complete`
4. Re-run dependent task

### Tool Not Found

**Problem:** Phase requires external tool that's not installed

**Solution:**
1. Check phase `tools` array in workflow YAML
2. Install missing tool (installation command provided by Claude)
3. Verify installation with `which <tool>`
4. Re-run phase task

## Extension Points

### Custom Workflows

Create new workflow YAML in `workflows/` directory:

```yaml
id: custom-engagement
name: Custom Engagement Type
kill_chain: classic
phases:
  scope:
    skills: [recon-osint]
    agents: [redteam-planner]
    templates: [scope/scope-definition.md]
    gate:
      required: [targets_defined]
    next: recon
  # ... additional phases
```

### Custom Gates

Add custom validation logic in gate config:

```yaml
gate:
  required: [artifact.md]
  validation: check_custom_requirement
```

Implement validation function in workflow engine.

### Custom Templates

Add templates to `templates/<phase>/` directory:

```markdown
---
phase: custom_phase
status: draft
gate: [custom_requirement]
depends_on: []
produces: [output.md]
---

# Custom Template

[template content]
```

Reference in workflow YAML:

```yaml
custom_phase:
  templates: [custom_phase/custom-template.md]
```

## State Management

### State Persistence

State is persisted in `.engage/state.json` after every:
- Phase transition
- Artifact creation/update
- Finding creation/update
- Gate validation

### State Recovery

If engagement is interrupted:

```bash
# Resume from last state
/engage resume

# Claude reads .engage/state.json
# Loads current phase
# Presents incomplete artifacts
```

### State Export

```bash
# Export engagement state
/engage export --format json > engagement-state.json

# Import engagement state
/engage import engagement-state.json
```

## Security Considerations

### Sensitive Data

- **Never commit** `.engage/` directory to version control
- **Encrypt** `.engage/` directory for long-term storage
- **Sanitize** findings before sharing reports
- **Redact** credentials, tokens, PII from artifacts

### Authorization Tracking

- **Scope phase** must document authorization
- **Gate validation** checks authorization artifact exists
- **Report phase** references authorization document
- **Emergency contacts** documented in scope phase

### OPSEC

- **OPSEC checklist** in C2 phase template
- **Source IP tracking** in recon plan
- **Tool fingerprints** documented
- **Cleanup plan** in install phase

## Performance

### Parallel Execution

Some phases support parallel task execution:

```yaml
recon:
  parallel: true  # Enable parallel skill execution
  skills: [recon-osint, vulnerability-scanner]
```

Claude can run multiple skills simultaneously in parallel mode.

### Incremental Validation

Validate artifacts incrementally instead of waiting for phase completion:

```bash
# Validate specific artifact
/phase validate scope/scope-definition.md

# Validate all completed artifacts
/phase validate --completed
```

## Metrics

Track engagement metrics in state file:

```json
{
  "metrics": {
    "phase_durations": {
      "scope": 3600,
      "recon": 14400
    },
    "findings_by_severity": {
      "critical": 2,
      "high": 5,
      "medium": 8
    },
    "tools_used": ["nmap", "nuclei", "ffuf"],
    "skills_invoked": ["recon-osint", "web-pentest"]
  }
}
```

## Autopilot Engine (`engine/`)

`engine/engine.py` is an optional **bounded, resumable, traceable runner** for a workflow. It is a
deterministic scaffold — **not** an LLM brain (no LangGraph/Ollama). It sequences a workflow's phases
under hard discipline and runs only registered SAFE actions; offensive technique execution stays with
the operator/skills and is gated by `action_guard.py`. The engine enforces the control loop.

```bash
python engine/engine.py run --workflow web-app-pentest --target api.acme.com \
    --scope .engage/scope/scope.json --state .engage/engine \
    --max-steps 50 --max-seconds 7200 --min-steps 3
# resume after interruption (skips completed steps from the trace):
python engine/engine.py run --workflow web-app-pentest --target api.acme.com --state .engage/engine --resume
```

Controls (the "no rabbit hole" discipline):

- **Budget** (`engine/budget.py`) — hard `--max-steps` and `--max-seconds` ceilings; `--min-steps`
  before the run may declare itself finished (can't bail on step 1).
- **Loop detector** (`engine/loop_detector.py`) — a sliding window of action signatures; when a move
  recurs `max_repeats` times it is flagged as a loop and the engine pivots/skips instead of hammering.
- **Tracer** (`engine/tracer.py`) — append-only JSONL trace at `<state>/trace.jsonl`; crash-safe and the
  basis for `--resume` (completed `step_id`s are skipped).
- **Operator bump** — drop a directive in `<state>/bump.txt`; it is recorded into the trace and consumed
  between steps (inject an extra target / change of plan mid-run).

Plan derivation: phases are ordered by following each phase's `next`; a `scope_check` (via `scope_guard.py`)
is inserted at scope when a `--target` is given, and a memory `recall` (via `pattern_db.py`) at recon/weaponize.
Built-in actions: `phase`, `scope_check`, `recall`, `note`. Register more in `ACTIONS` only for safe,
deterministic steps — keep destructive/offensive execution operator-gated. Use `/engage.pickup` to resume.

## References

- **Kill Chain:** Lockheed Martin Cyber Kill Chain
- **MITRE ATT&CK:** https://attack.mitre.org/
- **CWE:** https://cwe.mitre.org/
- **CVSS:** https://www.first.org/cvss/
- **PTES:** http://www.pentest-standard.org/
