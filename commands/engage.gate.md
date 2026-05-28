---
description: Run gate validation on the current phase before proceeding
---

# /engage.gate

Validates that the current phase meets all completion criteria before advancing to the next phase.

## Usage

`/engage.gate [--phase <phase-number>]`

If no phase specified, validates the current active phase.

## Validation Checks

### Artifact Validation
- All required template files are populated
- No placeholder text remains (e.g., "[TODO]", "[FILL IN]")
- Required sections contain substantive content

### Finding Validation
For phases that produce findings (recon, exploit, actions):
- Each finding has: title, severity, CWE/CVE, description, evidence path
- Evidence files exist at specified paths
- Findings follow the standard format

### Phase-Specific Checks

**Phase 0 (Scope)**:
- Target list defined
- Rules of Engagement documented
- Authorization evidence present
- Emergency contacts listed

**Phase 1 (Recon)**:
- Attack surface map populated
- At least one subdomain/host discovered
- Port scan results present
- Technology fingerprint documented

**Phase 2 (Weaponization)**:
- Target vulnerability selected
- Payload type chosen
- Mitigation bypass strategy documented

**Phase 4 (Exploitation)**:
- At least one successful exploit documented
- Finding record created with all required fields
- Evidence captured (screenshot or output)

**Phase 8 (Reporting)**:
- All findings from previous phases included
- Executive summary written
- Technical details complete
- Remediation guidance provided

## Output

### Pass
```
✓ Phase 2 (Weaponization) gate validation PASSED

All required artifacts present:
✓ exploit-blueprint.md (complete)
✓ payload-config.md (complete)

Validation checks:
✓ Target vulnerability selected (CVE-2024-1234)
✓ Payload type documented (reverse shell)
✓ Mitigation bypass strategy present

Ready to proceed to Phase 3 (Delivery).
Run: /engage.deliver
```

### Fail
```
✗ Phase 2 (Weaponization) gate validation FAILED

Missing artifacts:
✗ payload-config.md incomplete (missing C2 configuration)

Validation failures:
✗ No mitigation bypass strategy documented
✗ Placeholder text found in exploit-blueprint.md

Fix these issues before proceeding.
```

## Notes

Gate validation is mandatory before advancing phases. This ensures engagement quality and prevents skipping critical steps.
