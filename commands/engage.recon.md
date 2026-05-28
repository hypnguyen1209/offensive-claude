---
description: Execute Phase 1 - Reconnaissance and Attack Surface Mapping
---

# /engage.recon

Executes Phase 1 (Reconnaissance) of the engagement workflow.

## Usage

`/engage.recon [--passive-only] [--active]`

Options:
- `--passive-only`: Only passive reconnaissance (no direct target interaction)
- `--active`: Include active scanning (default if authorized in scope)

## Process

### 1. Load Templates
Loads:
- `recon/recon-plan.md` — Reconnaissance methodology
- `recon/attack-surface.md` — Attack surface map template

### 2. Passive Reconnaissance
Executes in order:

**Subdomain Enumeration**:
- Certificate transparency logs (crt.sh)
- DNS enumeration (subfinder, amass)
- Search engine dorking
- Historical DNS records

**OSINT Gathering**:
- WHOIS information
- Company information (LinkedIn, Crunchbase)
- Email addresses and naming conventions
- Technology stack identification (BuiltWith, Wappalyzer)
- GitHub/GitLab repository discovery
- Pastebin/leak searches

**Infrastructure Mapping**:
- ASN and IP range identification
- Cloud provider detection (AWS/Azure/GCP)
- CDN and WAF detection

### 3. Active Reconnaissance
If authorized:

**Port Scanning**:
- Full TCP port scan on discovered hosts
- Service version detection
- OS fingerprinting

**Service Enumeration**:
- HTTP/HTTPS service discovery
- Banner grabbing
- SSL/TLS configuration analysis

**Web Application Fingerprinting**:
- CMS detection (WordPress, Drupal, etc.)
- Framework identification
- JavaScript library analysis
- API endpoint discovery

### 4. Attack Surface Mapping
Populates `recon/attack-surface.md` with:
- Discovered subdomains and hosts
- Open ports and services
- Web applications and entry points
- Identified technologies and versions
- Potential attack vectors
- High-value targets

### 5. Gate Check
Validates:
- At least one subdomain/host discovered
- Port scan results present (if active recon authorized)
- Technology fingerprint documented
- Attack surface map populated

### 6. Next Steps
If gate passes, suggests: `/engage.weaponize`

## Available Skills

This phase can invoke:
- `01-recon-osint` — Comprehensive OSINT gathering
- `02-vulnerability-scanner` — Automated vulnerability scanning
- `09-web-security` — Web application reconnaissance

## Example Output

```
Starting Phase 1: Reconnaissance

Target: acme-corp.com
Mode: Active reconnaissance authorized

[1/3] Passive Reconnaissance
→ Subdomain enumeration...
  Found 47 subdomains via certificate transparency
  Found 23 subdomains via DNS brute force
  Total unique subdomains: 58

→ OSINT gathering...
  WHOIS: Registered to ACME Corporation
  Email pattern: firstname.lastname@acme-corp.com
  Technologies: Nginx, React, AWS

[2/3] Active Reconnaissance
→ Port scanning 58 hosts...
  12 hosts with port 80/443 open
  3 hosts with port 22 open
  1 host with port 3389 open

→ Service enumeration...
  Web servers: Nginx 1.21.0 (8), Apache 2.4.41 (4)
  SSH: OpenSSH 8.2p1 (3)
  RDP: Windows Server 2019 (1)

[3/3] Attack Surface Mapping
→ Populating attack-surface.md...
  Entry points: 12 web applications
  High-value targets: admin.acme-corp.com, api.acme-corp.com
  Potential vectors: Outdated Nginx, exposed RDP

Reconnaissance complete.
Running gate validation...

✓ Phase 1 (Reconnaissance) gate validation PASSED
Ready to proceed to Phase 2 (Weaponization).
Run: /engage.weaponize
```

## Notes

Reconnaissance is the foundation of the engagement. Thorough recon leads to better targeting and higher success rates.
