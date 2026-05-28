---
phase: delivery
status: draft
gate: [delivery_executed]
depends_on: [weaponize/exploit-blueprint.md, weaponize/payload-config.md]
produces: [exploit/exploit-plan.md]
---

# Delivery Plan

## Delivery Vector

| Field | Value |
|-------|-------|
| Method | Web exploit / Phishing / Physical / Supply chain / Service exploit |
| Target | |
| Payload | |
| Trigger | User action / Automatic / Time-based |

## Execution Plan

### Pre-Delivery Checks

- [ ] Payload tested and functional
- [ ] Delivery infrastructure ready
- [ ] OPSEC review completed
- [ ] Monitoring in place for callback

### Delivery Steps

| Step | Action | Expected Result | Fallback |
|------|--------|-----------------|----------|
| 1 | | | |
| 2 | | | |
| 3 | | | |

### Post-Delivery

- [ ] Confirm payload delivery
- [ ] Monitor for callback/execution
- [ ] Check for detection alerts
- [ ] Document delivery timestamp

## Infrastructure

| Component | Detail |
|-----------|--------|
| Delivery server | |
| Redirector | |
| Domain | |
| SSL cert | |
| Hosting | |

## OPSEC

| Indicator | Risk Level | Mitigation |
|-----------|-----------|-----------|
| Email headers | | |
| Domain reputation | | |
| Payload hash | | |
| Network traffic | | |

## Contingency

If delivery fails:
1. **Retry:** [conditions for retry]
2. **Pivot:** [alternative delivery method]
3. **Abort:** [conditions to abort]
