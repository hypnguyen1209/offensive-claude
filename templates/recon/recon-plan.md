---
phase: recon
status: draft
gate: [targets_confirmed, tools_selected, opsec_defined]
depends_on: [scope/scope-definition.md]
produces: [recon/attack-surface.md]
---

# Reconnaissance Plan

## Targets

From scope definition:

| Target | Type | Priority | Approach |
|--------|------|----------|----------|
| | | P1/P2/P3 | Passive / Active / Both |

## Methodology

### Phase 1: Passive Reconnaissance

| Task | Tool | Status |
|------|------|--------|
| Subdomain enumeration | subfinder, amass, crt.sh | |
| DNS records | dig, whois | |
| Technology fingerprinting | httpx, whatweb | |
| Certificate transparency | crt.sh | |
| Wayback URL discovery | waybackurls | |
| Breach/credential lookup | h8mail, HIBP | |
| GitHub/code search | manual dorking | |
| Cloud asset discovery | S3/blob enumeration | |

### Phase 2: Active Reconnaissance

| Task | Tool | Status |
|------|------|--------|
| Port scanning | nmap | |
| Service enumeration | nmap -sV | |
| Web crawling | katana, feroxbuster | |
| Directory fuzzing | ffuf, feroxbuster | |
| API endpoint discovery | ffuf, katana | |
| Vulnerability scanning | nuclei | |

## OPSEC Constraints

| Constraint | Value |
|------------|-------|
| Scan rate limit | |
| Source IP | |
| User-Agent | |
| Time window | |
| Noise level | Low / Medium / High |

## Expected Outputs

- [ ] Subdomain list (all_subdomains.txt)
- [ ] Live hosts with technologies (httpx_results.txt)
- [ ] Open ports and services (nmap_targeted.*)
- [ ] Directory/endpoint map
- [ ] CVE list for identified components
- [ ] Credential/breach data
- [ ] Attack surface summary (attack-surface.md)
