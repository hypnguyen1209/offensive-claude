---
description: Run gate validation on the current phase before proceeding
---

# /engage.gate

Validates that the current phase meets all completion criteria before advancing to the next phase.

## Usage

`/engage.gate [--phase <phase-number>]`

If no phase specified, validates the current active phase.

## Validation Checks

### Automated Enforcement (run these, don't just eyeball)

These executable checks back the gate — a phase cannot pass if they fail:

```bash
# Scope is enforced, not promised: every in-scope target must classify in-scope,
# and the scope file itself must be valid.
python skills/coding-mastery/scripts/_lib/scope_guard.py check <target> \
    --scope .engage/scope/scope.json

# Evidence must be re-verifiable: re-hash every captured artifact before trusting a citation.
# Exit 1 if any item is FAILED/UNVERIFIED (tampered, missing, or never hashed).
python skills/vulnerability-analysis/scripts/evidence_kit.py verify \
    --store .engage/evidence/evidence.json

# Findings must be grounded in evidence and survive per-class kill-signals.
# --evidence-store makes any [EVD-XXX] a finding cites have to EXIST and be VERIFIED, else REJECTED.
# --strict makes hedge / uncited lint on a CONFIRMED finding also fail the gate.
# Exit 1 if any finding is REJECTED (ungrounded / false-positive / dangling-or-unverified citation).
python skills/vulnerability-analysis/scripts/validate_findings.py \
    --findings .engage/exploit/findings.json --evidence .engage/evidence \
    --evidence-store .engage/evidence/evidence.json --strict
```

A finding only passes the gate if `validate_findings.py` tiers it **CONFIRMED** (or a
documented **CHAIN-REQUIRED**). `POSSIBLE`/`REJECTED` findings do not advance. **No finding advances
past the exploit gate while it cites UNVERIFIED evidence** — run `evidence_kit.py verify` first. See
`skills/references/finding-validation-runtime.md` and `finding-evidence-standards.md`.

### Artifact Validation
- All required template files are populated
- No placeholder text remains (e.g., "[TODO]", "[FILL IN]")
- Required sections contain substantive content

### Finding Validation
For phases that produce findings (recon, exploit, actions):
- Each finding has: title, severity, CWE/CVE, description, evidence path
- Evidence files exist at specified paths (enforced by `validate_findings.py` grounding check)
- Findings follow the standard format and carry a confidence tier: `[CONFIRMED]` / `[POSSIBLE]` / `[INFO]`
- Per-class exploitability bar met (no self-IDOR, DNS-only SSRF, encoded "XSS", same-origin "redirect", blind "RCE")

### Phase-Specific Checks

**Phase 0 (Scope)**:
- Target list defined
- **`.engage/scope/scope.json` emitted and valid** (loads in `scope_guard.py`; matches `templates/scope/scope.schema.json`)
- Rules of Engagement documented
- Authorization evidence present (`authorization_ref` set)
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
