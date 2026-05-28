---
description: Execute Phase 6 - Command and Control Infrastructure Setup
---

# /engage.c2

Executes Phase 6 (Command and Control) of the engagement workflow.

## Usage

`/engage.c2 [--framework <framework>] [--protocol <protocol>]`

Options:
- `--framework`: C2 framework (cobalt-strike, sliver, mythic, havoc, custom)
- `--protocol`: Communication protocol (https, dns, smb, tcp)

## Process

### 1. Load Templates
Loads:
- `c2/c2-infrastructure.md` — C2 architecture and configuration
- `c2/opsec-checklist.md` — Operational security checklist

### 2. C2 Framework Selection
Based on engagement requirements:

**Framework Options**:
- **Cobalt Strike**: Industry standard, Malleable C2 profiles, BOF support
- **Sliver**: Open-source, cross-platform implants, multiplayer
- **Mythic**: Modular agents, web UI, extensive logging
- **Havoc**: Modern framework, evasion-focused, Demon agent
- **Custom**: Purpose-built for specific engagement needs

**Protocol Selection**:
- **HTTPS**: Standard web traffic (port 443), high blend-in
- **DNS**: Low-and-slow exfiltration, bypasses most firewalls
- **SMB**: Internal lateral movement, named pipe communication
- **TCP**: Direct connection, fastest but most detectable

### 3. Infrastructure Setup
Documents in `c2-infrastructure.md`:

**Architecture Design**:
- C2 server location and hardening
- Redirector configuration (Apache/Nginx/CDN)
- Domain categorization and aging
- SSL/TLS certificate setup

**Redirector Configuration**:
- Frontend redirector (filters non-C2 traffic)
- Backend C2 server (hidden from target)
- Domain fronting setup (if applicable)
- CDN-based redirection (Cloudflare, AWS CloudFront)

**Communication Profile**:
- Beacon interval and jitter
- HTTP headers and URI patterns
- User-Agent strings
- Payload encryption (AES, ChaCha20)
- Data encoding (base64, custom)

**Infrastructure Hardening**:
- Firewall rules (only accept beacon traffic)
- SSH access controls
- Logging configuration
- Kill switch mechanism

### 4. Beacon Verification
After setup:
- Confirm beacon callback from target
- Verify C2 command execution
- Test data exfiltration channel
- Validate encryption is functioning
- Check beacon stability over time

### 5. OPSEC Checklist
Reviews `opsec-checklist.md`:

**Network OPSEC**:
- [ ] C2 traffic blends with legitimate traffic
- [ ] Domain categorization is appropriate (not "Malware")
- [ ] SSL certificate appears legitimate
- [ ] Beacon interval is appropriate (not too frequent)
- [ ] DNS requests appear normal
- [ ] No hardcoded IPs in payloads

**Infrastructure OPSEC**:
- [ ] C2 server not directly exposed to target
- [ ] Redirectors filter invalid traffic
- [ ] Kill switch tested and functional
- [ ] Server hardened (no unnecessary services)
- [ ] Logs secured and encrypted

**Payload OPSEC**:
- [ ] Payload does not beacon to IP directly
- [ ] Communication is encrypted
- [ ] Payload strings are obfuscated
- [ ] No PII or attribution data in payload

### 6. Gate Check
Validates:
- C2 framework configured
- Redirector(s) operational
- Beacon callback verified
- OPSEC checklist completed (all items addressed)
- Communication profile documented

### 7. Next Steps
If gate passes, suggests: `/engage.actions`

## Example Output

```
Starting Phase 6: Command and Control

C2 Framework: Sliver
Protocol: HTTPS (mutual TLS)

[1/4] Infrastructure Setup
→ C2 Server: vps-c2.example.com (198.51.100.10)
  - Hardened Ubuntu 22.04
  - UFW: Only 443/tcp from redirector

→ Redirector: redirect01.example.com (203.0.113.50)
  - Nginx reverse proxy
  - Filters traffic by User-Agent and URI
  - Valid Let's Encrypt SSL certificate
  - Domain categorized as "Business/Technology"

→ Communication Profile:
  Beacon interval: 60 seconds
  Jitter: 30%
  HTTP Path: /api/v2/status
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
  Encryption: mTLS + AES-256-GCM

[2/4] Beacon Verification
→ Checking active implants...
  Implant: ADMIN-ACME-42
  Host: admin.acme-corp.com
  User: root
  Last callback: 15 seconds ago
  Status: Active

→ Testing C2 commands...
  ✓ execute: whoami → root
  ✓ upload: test.txt → /tmp/test.txt
  ✓ download: /etc/hostname → hostname.txt

[3/4] OPSEC Checklist
✓ C2 traffic blends with HTTPS web traffic
✓ Domain categorized as "Business/Technology"
✓ SSL certificate is valid Let's Encrypt
✓ Beacon interval 60s with 30% jitter
✓ Redirector filters invalid requests (returns 404)
✓ C2 server not directly exposed
✓ Kill switch tested (deregister command functional)
✓ All communication encrypted (mTLS)

[4/4] Documentation
→ C2 infrastructure documented
→ Connection details recorded
→ Kill switch procedures documented

Running gate validation...

✓ Phase 6 (C2) gate validation PASSED
Ready to proceed to Phase 7 (Actions on Objectives).
Run: /engage.actions
```

## Available Skills

- `14-red-team-ops` — C2 infrastructure and operations
- `24-advanced-redteam` — Advanced C2 and OPSEC
- `08-network-security` — Network traffic analysis

## Notes

C2 infrastructure is the lifeline of the engagement. Invest time in proper setup and OPSEC to avoid detection.
