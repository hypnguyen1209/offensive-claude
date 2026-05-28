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

### 3. Validation
Checks that all required fields are populated with substantive content.

### 4. Gate Check
Runs `/engage.gate` automatically to validate:
- All sections complete
- Authorization documented
- ROE clearly defined
- Contacts provided

### 5. Next Steps
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
