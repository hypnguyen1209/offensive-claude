---
phase: install
status: draft
gate: [persistence_documented, cleanup_planned]
depends_on: [exploit/exploit-plan.md]
produces: [c2/c2-infrastructure.md]
---

# Persistence Mechanism

## Access Maintained

| Field | Value |
|-------|-------|
| Target system | |
| User context | NT AUTHORITY\SYSTEM / root / user |
| Access type | Shell / Beacon / Web shell / Backdoor |
| Reliability | High / Medium / Low |

## Persistence Method

| Method | Detail |
|--------|--------|
| Type | Service / Scheduled task / Startup / Registry / Cron / Web shell / DLL hijack |
| Name | |
| Location | |
| Trigger | Boot / User login / Timer / Event |

### Installation Steps

1. [Step 1]
2. [Step 2]
3. [Step 3]

### Verification

- [ ] Mechanism survives reboot
- [ ] Mechanism runs at correct privilege
- [ ] No unintended side effects
- [ ] Only accessible by engagement team

## OPSEC

| Indicator | Detection Risk | Evasion |
|-----------|---------------|---------|
| Registry key | Low/Med/High | |
| File on disk | Low/Med/High | |
| Service/process | Low/Med/High | |
| Network connection | Low/Med/High | |

## Detection Timeline

| Event | Time | Expected duration of access |
|-------|------|---------------------------|
| Installation | | |
| Regular check-in | | |
| Expected discovery | | |
| Expiration/kill date | | |

## Cleanup Plan

### Manual removal

| Step | Action |
|------|--------|
| 1 | |
| 2 | |
| 3 | |

### Automatic removal script

```bash
# [cleanup script]
```

### Verification of cleanup

- [ ] Persistence mechanism removed
- [ ] Files deleted
- [ ] Registry keys removed
- [ ] Logs cleared (if authorized)
- [ ] System returned to original state

### Fallback

If auto-cleanup fails:
