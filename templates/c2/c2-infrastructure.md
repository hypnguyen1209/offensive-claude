---
phase: c2
status: draft
gate: [c2_channel_established]
depends_on: [install/persistence-mechanism.md]
produces: [actions/objectives.md]
---

# C2 Infrastructure

## Architecture

```
┌─────────┐     ┌──────────┐     ┌──────────┐     ┌────────┐
│  Beacon  │ ←─→ │ Redirector│ ←─→ │  C2 Server │ ←─→ │   Team │
│  (target)│     │ (CDN/Jump)│     │  (VPS)    │     │  Server│
└─────────┘     └──────────┘     └──────────┘     └────────┘
```

## Components

### C2 Server

| Field | Value |
|-------|-------|
| Provider | |
| IP/FQDN | |
| Port | |
| Protocol | HTTPS / DNS / SMB / TCP |
| Framework | CobaltStrike / Mythic / Sliver / Nighthawk / Havoc / Empire |
| Profile | |

### Redirector(s)

| Field | Value |
|-------|-------|
| Type | Nginx reverse proxy / CDN / Domain fronting |
| Provider | |
| Domain | |
| SSL | Let's Encrypt / Custom / CDN |

### Beacon Configuration

| Field | Value |
|-------|-------|
| Sleep | |
| Jitter | |
| User-Agent | |
| HTTP headers | |
| URI paths | |
| Kill date | |
| Max retry | |

## Malleable Profile (if applicable)

### Key Settings

| Setting | Value |
|---------|-------|
| Sample file | |
| Metadata | |
| Staging | |
| Post-ex | |
| Process inject | |

## OPSEC Checklist

- [ ] C2 server hardened (SSH keys, firewall, no root login)
- [ ] Redirector logging minimal
- [ ] Domains not linked to tester identity
- [ ] SSL cert valid and trusted
- [ ] Fallback C2 configured
- [ ] DNS records don't reveal C2
- [ ] Beacon traffic blends with normal traffic
- [ ] C2 server disposal plan documented
