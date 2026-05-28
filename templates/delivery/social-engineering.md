---
phase: delivery
status: draft
gate: [pretext_defined, targets_identified]
depends_on: [recon/attack-surface.md]
produces: [delivery/delivery-plan.md]
---

# Social Engineering Plan

## Campaign Overview

| Field | Value |
|-------|-------|
| Type | Phishing / Vishing / Smishing / Physical / Pretexting |
| Objective | Credential harvest / Payload delivery / Physical access |
| Target audience | |
| Campaign duration | |

## Pretext

| Element | Detail |
|---------|--------|
| Scenario | |
| Sender persona | |
| Urgency trigger | |
| Call to action | |
| Landing page | |

## Targets

| Name | Role | Email | Priority | Notes |
|------|------|-------|----------|-------|
| | | | P1/P2/P3 | |

## Materials

### Email/Message Template

```
Subject:
From:
Body:

[template content]
```

### Landing Page

| Element | Detail |
|---------|--------|
| URL | |
| Clone of | |
| Credential fields | |
| Redirect after | |

## Infrastructure

| Component | Detail |
|-----------|--------|
| Sending domain | |
| SMTP server | |
| Landing page host | |
| SSL certificate | |
| Tracking pixel | |

## Success Metrics

| Metric | Target |
|--------|--------|
| Emails sent | |
| Emails opened | |
| Links clicked | |
| Credentials captured | |
| Payloads executed | |

## OPSEC

- [ ] Domain age > 30 days
- [ ] SPF/DKIM/DMARC configured
- [ ] No link to attacker infrastructure
- [ ] Tracking minimal and covert
