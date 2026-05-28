---
phase: scope
status: draft
gate: [contacts_defined]
depends_on: [scope/scope-definition.md]
produces: []
---

# Emergency Contact & Escalation

## Incident Escalation Path

```
Level 1: Technical issue (system down, unexpected behavior)
  → Contact: Technical POC
  → Response: 15 minutes

Level 2: Security incident (data exposure, service impact)
  → Contact: Client POC + Engagement Lead
  → Response: Immediate

Level 3: Legal/compliance issue
  → Contact: Legal counsel + Client executive
  → Response: Immediate, halt all testing
```

## Contacts

| Level | Name | Phone | Email | Availability |
|-------|------|-------|-------|--------------|
| Technical POC | | | | |
| Client POC | | | | |
| Engagement Lead | | | | |
| Legal Counsel | | | | |

## Halt Conditions

Testing MUST stop immediately if:

- [ ] Unauthorized data accessed (PII, financial, health records)
- [ ] Production system impacted beyond scope
- [ ] Third-party system affected
- [ ] Law enforcement contact received
- [ ] Client requests immediate halt

## Incident Response

If halt condition triggered:

1. Stop all active testing immediately
2. Document current state and actions taken
3. Contact Level 2 escalation within 5 minutes
4. Preserve all evidence and logs
5. Do NOT attempt to "fix" or "clean up" without authorization
6. Await instructions before resuming
