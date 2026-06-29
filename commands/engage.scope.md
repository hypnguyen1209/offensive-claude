---
description: Execute Phase 0 - Scope Definition and Rules of Engagement
---

# /engage.scope

Executes Phase 0 (Scope Definition) of the engagement workflow.

## Usage

`/engage.scope`

## Process

### 1. Load Template
Loads `scope/scope-definition.md` template with sections:
- Engagement Overview
- Target Information
- Rules of Engagement (ROE)
- Authorization
- Scope Boundaries (in-scope / out-of-scope)
- Emergency Contacts
- Timeline

### 2. Interactive Scope Definition
Works with you to populate:

**Target Information**:
- Primary targets (domains, IP ranges, applications)
- Target environment (production/staging/dev)
- Technology stack (if known)

**Rules of Engagement**:
- Allowed testing hours
- Prohibited actions (DoS, social engineering, physical access)
- Data handling requirements
- Notification procedures

**Authorization**:
- Authorization letter/email reference
- Authorized contact name and role
- Authorization scope and limitations

**Scope Boundaries**:
- Explicitly in-scope assets
- Explicitly out-of-scope assets (third-party services, shared infrastructure)

**Emergency Contacts**:
- Primary technical contact
- Security team contact
- Escalation contact
- After-hours contact

**Timeline**:
- Engagement start date
- Engagement end date
- Reporting deadline

### 3. Emit machine-readable scope (`scope.json`)
Translate the in-scope / out-of-scope boundaries into `.engage/scope/scope.json` following
`templates/scope/scope.schema.json` (see `templates/scope/scope.example.json`). This file is
the **enforced** boundary — every active script consults it via `scope_guard.py`, so "stay in
scope" stops being a promise and becomes a check.

```bash
mkdir -p .engage/scope
# ...write scope.json with engagement, authorization_ref, in_scope[], out_of_scope[], roe{}...
# Sanity-check it loads and that a known in-scope target classifies correctly:
python skills/coding-mastery/scripts/_lib/scope_guard.py check api.acme.com \
    --scope .engage/scope/scope.json
```

Remember: `*.acme.com` matches sub-domains only — list the apex `acme.com` separately;
`out_of_scope` always wins.

### 4. Validation
Checks that all required fields are populated with substantive content, and that
`scope.json` loads without error.

### 5. Gate Check
Runs `/engage.gate` automatically to validate:
- All sections complete
- `scope.json` present and valid
- Authorization documented
- ROE clearly defined
- Contacts provided

### 6. Next Steps
If gate passes, suggests: `/engage.recon`

## Example Interaction

```
Let's define the engagement scope.

Target Information:
What is the primary target? (domain, IP range, or application URL)
> acme-corp.com and *.acme-corp.com

Is this a production environment?
> Yes

Rules of Engagement:
Are there any time restrictions for testing?
> Business hours only (9 AM - 5 PM EST, Monday-Friday)

Are DoS/resource exhaustion attacks permitted?
> No

[... continues through all sections ...]

Scope definition complete.
Running gate validation...

✓ Phase 0 (Scope) gate validation PASSED
Ready to proceed to Phase 1 (Reconnaissance).
Run: /engage.recon
```

## Notes

Proper scoping is critical for legal protection and engagement success. Never skip this phase.
