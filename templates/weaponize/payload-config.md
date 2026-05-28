---
phase: weaponize
status: draft
gate: [payload_configured]
depends_on: [weaponize/exploit-blueprint.md]
produces: [delivery/delivery-plan.md]
---

# Payload Configuration

## Payload Specification

| Parameter | Value |
|-----------|-------|
| Type | |
| Generator | msfvenom / custom / pwntools / donut / ScareCrow |
| Format | exe / dll / ps1 / py / shellcode / csharp |
| Architecture | x86 / x64 |
| Staging | Staged / Stageless |

## C2 Configuration

| Parameter | Value |
|-----------|-------|
| Callback host | |
| Callback port | |
| Protocol | HTTPS / DNS / SMB / TCP |
| Sleep interval | |
| Jitter | |
| Kill date | |
| User-agent | |

## Encoding & Evasion

| Layer | Technique | Tool |
|-------|-----------|------|
| Encryption | AES / XOR / RC4 | |
| Packing | UPX / custom | |
| Obfuscation | String encrypt / control flow | |
| Loader | Reflective / Syscall / Early Bird | |
| Sandbox evasion | Sleep / Environment check / User interaction | |

## Generation Commands

```bash
# Primary payload
# [exact command here]

# Backup payload
# [exact command here]
```

## Testing Checklist

- [ ] Payload generates without error
- [ ] Payload executes in test environment
- [ ] Callback received on C2
- [ ] AV/EDR scan: detection rate
- [ ] Size within constraints
- [ ] Bad characters eliminated
- [ ] Kill date functional
