---
phase: c2
status: draft
gate: [opsec_review_completed]
depends_on: [c2/c2-infrastructure.md]
produces: [actions/collection-plan.md]
---

# OPSEC Checklist

## Infrastructure OPSEC

| Check | Status | Notes |
|-------|--------|-------|
| C2 VPS registered with anonymous payment | | |
| C2 VPS registered with fake/no identity | | |
| Redirector CDN configured | | |
| Domains purchased anonymously | | |
| No personal data on C2 infra | | |
| C2 logs configured minimal/no-store | | |
| SSH keys only, no passwords | | |
| C2 ports not standard ports (80/443) | | |

## Communication OPSEC

| Check | Status | Notes |
|-------|--------|-------|
| Beacon traffic encrypted | | |
| Beacon imitates legitimate service | | |
| JA3/JA3S signature randomized | | |
| Beacon sleep + jitter > 30s | | |
| User-Agent matches target environment | | |
| DNS requests blend with normal traffic | | |
| No plaintext C2 domain in packets | | |

## Operational OPSEC

| Check | Status | Notes |
|-------|--------|-------|
| Testing hours within scope | | |
| Source IP rotates regularly | | |
| No identifiable tools in network traffic | | |
| Lateral movement uses native tools (LOLBins) | | |
| No engagement data stored on target | | |
| Credentials encrypted in transit and rest | | |
| Screenshots contain no tester identity | | |

## Detection Risk Matrix

| Activity | Detection Likelihood | Blue Team Notify Time | Mitigation |
|----------|---------------------|---------------------|------------|
| Port scan | Low | Variable | Use proxy chains |
| Exploit | Medium | Immediate | Use obfuscation |
| Persistence | Medium | Hours | Use common paths |
| Lateral movement | High | Minutes | Use LOLBins |
| Data collection | Low | Hours | Stay in memory |
| Exfiltration | High | Immediate | Encrypt + throttle |
