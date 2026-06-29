---
name: recon-osint
description: Reconnaissance & OSINT — passive/active subdomain enumeration, attack-surface mapping (httpx/katana/JS secrets), subdomain takeover (incl. S3 supply-chain pivot), multi-cloud + Azure tenant recon, GitHub/GitLab secret dorking, breach/infostealer credential intelligence (HIBP v3, DeHashed), and CVE prioritization (NVD 2.0 / EPSS v4 / CISA KEV)
metadata:
  type: offensive
  phase: reconnaissance
  tools: subfinder, amass, puredns, dnsx, httpx, katana, gau, nuclei, subzy, baddns, cloud_enum, AADInternals, trufflehog, gitleaks, theHarvester, h8mail, shodan, censys
  mitre: TA0043
kill_chain:
  phase: [recon]
  step: [1]
  attck_tactics: [TA0043, TA0006]
  attck_techniques: [T1595, T1595.002, T1590, T1590.001, T1590.002, T1590.005, T1592, T1592.002, T1589, T1589.001, T1589.002, T1593, T1593.001, T1593.003, T1596, T1596.005, T1591, T1583.001, T1213.003]
depends_on: []
feeds_into: [vulnerability-analysis, web-pentest, network-attack, exploit-development, cloud-security, mobile-pentest, active-directory-attack, initial-access]
inputs: [scope_definition, target_list, root_domains, asn_list, email_list]
outputs: [attack_surface_map, subdomain_list, technology_fingerprint, cve_list, takeover_candidates, leaked_secrets, breach_intel, prioritized_findings]
references:
  - references/subdomain-discovery.md
  - references/attack-surface-mapping.md
  - references/subdomain-takeover.md
  - references/cloud-saas-recon.md
  - references/breach-credential-intel.md
  - references/cve-exploit-intel.md
scripts:
  - scripts/recon_orchestrator.py
  - scripts/subdomain_takeover.py
  - scripts/js_secret_hunter.py
  - scripts/cloud_asset_enum.py
  - scripts/breach_intel.py
  - scripts/cve_prioritizer.py
  - scripts/wordlist_ranker.py
  - scripts/hackerone_public_recon.py
---

# Reconnaissance & OSINT

## When to Activate

- A new engagement begins and you need a full external attack-surface map for a set of root domains / ASNs.
- Expanding scope: pivoting from one discovered asset (subdomain, IP block, cloud account) to the rest of the estate.
- Hunting dangling DNS / subdomain-takeover candidates, including S3 buckets referenced by CI/CD assets.
- Building a target profile for social engineering / initial access (emails, usernames, breach + infostealer exposure).
- Discovering leaked secrets in public GitHub/GitLab orgs and exposed cloud storage.
- Triaging which discovered CVEs actually matter (KEV + EPSS + exposure) before weaponization.

## Technique Map

| Technique | ATT&CK | CWE | Reference | Script |
|-----------|--------|-----|-----------|--------|
| Passive subdomain enum (subfinder/amass/CT logs) | T1590.002, T1596.001 | CWE-200 | references/subdomain-discovery.md | scripts/recon_orchestrator.py |
| DNS brute / permutation / resolution (puredns/alterx/dnsx) | T1595.002, T1590.002 | CWE-200 | references/subdomain-discovery.md | scripts/recon_orchestrator.py |
| ASN → CIDR → reverse-DNS expansion | T1590.005, T1596.005 | CWE-200 | references/subdomain-discovery.md | scripts/recon_orchestrator.py |
| HTTP probing + tech fingerprint (httpx) | T1595.002, T1592.002 | CWE-200 | references/attack-surface-mapping.md | scripts/recon_orchestrator.py |
| Headless crawling + archive URLs (katana/gau) | T1595.002, T1593.003 | CWE-200 | references/attack-surface-mapping.md | scripts/js_secret_hunter.py |
| JavaScript endpoint / secret extraction | T1593.003, T1552.001 | CWE-540 | references/attack-surface-mapping.md | scripts/js_secret_hunter.py |
| Subdomain takeover (dangling CNAME/NS) | T1583.001, T1584.001 | CWE-350 | references/subdomain-takeover.md | scripts/subdomain_takeover.py |
| Deleted-S3 takeover → supply-chain pivot | T1583.001, T1195.002 | CWE-350 | references/subdomain-takeover.md | scripts/subdomain_takeover.py |
| Multi-cloud bucket/blob enum (cloud_enum) | T1580, T1596.005 | CWE-732 | references/cloud-saas-recon.md | scripts/cloud_asset_enum.py |
| Azure tenant outsider recon (AADInternals) | T1590.001, T1589 | CWE-200 | references/cloud-saas-recon.md | scripts/cloud_asset_enum.py |
| GitHub/GitLab dorking + secret scanning | T1593.003, T1213.003 | CWE-540 | references/cloud-saas-recon.md | scripts/cloud_asset_enum.py |
| Email/username harvesting (theHarvester) | T1589.002, T1591 | CWE-200 | references/breach-credential-intel.md | scripts/breach_intel.py |
| Breach + infostealer credential intel (HIBP/DeHashed) | T1589.001, T1596 | CWE-522 | references/breach-credential-intel.md | scripts/breach_intel.py |
| CVE enrichment + prioritization (NVD/EPSS/KEV) | T1592.002, T1596 | CWE-1395 | references/cve-exploit-intel.md | scripts/cve_prioritizer.py |
| Shodan InternetDB exposure → CVE mapping | T1596.005, T1595.002 | CWE-200 | references/cve-exploit-intel.md | scripts/cve_prioritizer.py |

## Quick Start

```bash
export DOMAIN=target.com
# 0. Validate resolvers once (puredns needs a clean list)
dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 100 -o resolvers.txt

# 1. Full discovery + probe + crawl + takeover + nuclei, JSONL out (see orchestrator)
python3 scripts/recon_orchestrator.py -d $DOMAIN -o out/ --resolvers resolvers.txt --nuclei

# 2. JS/endpoint + secret hunting over live hosts
python3 scripts/js_secret_hunter.py -l out/httpx_live.txt -o out/js/

# 3. Dangling-DNS / subdomain-takeover triage
python3 scripts/subdomain_takeover.py -l out/all_subdomains.txt -o out/takeovers.jsonl

# 4. Cloud + code recon (buckets, Azure tenant, GitHub secrets)
python3 scripts/cloud_asset_enum.py -k $DOMAIN --company target --azure-domain $DOMAIN --gh-org target

# 5. People + breach/infostealer intel
python3 scripts/breach_intel.py --domain $DOMAIN --harvest --hibp --dehashed

# 6. Triage CVEs from fingerprints → KEV/EPSS/exposure ranked
python3 scripts/cve_prioritizer.py --from-httpx out/httpx_live.txt --ip-file out/ips.txt -o out/cve_ranked.jsonl
```

## OPSEC & Detection (summary)

| Technique | Telemetry / IOC | Detection (Sigma/EDR) | OPSEC note |
|-----------|-----------------|------------------------|------------|
| Passive enum (CT/API) | None on target; queries hit 3rd-party APIs | Target cannot see it; CT-log monitoring (certstream) detects *new* certs only | Fully passive — prefer for stealth; no target traffic |
| DNS brute / resolution | Burst of NXDOMAIN/A queries to authoritative + resolvers | DNS firewall: high-volume distinct-label rate per source IP; Zeek `dns.cc`/NXDOMAIN ratio | Throttle `-rate`, rotate resolvers, never brute a single auth NS directly |
| httpx / katana probing | Spike of HTTP(S) requests, odd UA, favicon/JARM fetches | WAF/CDN: request-rate + UA anomaly; access-log `User-Agent: *httpx*`/`*katana*` | Set custom UA, low `-rl`, route via proxy pool / cloud egress |
| Subdomain takeover check | HTTP GET to dangling host (lands on 3rd-party) | 3rd-party provider logs; CT for new cert on claimed host | Verify with passive fingerprint before any claim; claiming is loud |
| Cloud bucket enum | DNS + HTTP to `*.s3/blob/storage.googleapis` | Cloud provider access logs; GuardDuty `Discovery:S3/*` | Hits provider, not target; still rate-limited / loggable |
| Azure tenant recon | Requests to `login.microsoftonline.com` | Entra sign-in/audit logs do *not* see unauth realm probes | `getuserrealm`/OpenID are unauth & invisible to tenant |
| GitHub/GitLab dorking | API/search queries from your token | GitHub audit log (only org members'); secret-scanning alerts | Use a throwaway token; respect rate limits to avoid bans |
| Breach/infostealer lookup | 3rd-party API calls (HIBP/DeHashed) | None on target | Handle PII per ROE/GDPR; document lawful basis |
| CVE enrichment | NVD/EPSS/KEV/Shodan API calls | None on target | Map exposure to *in-scope* assets only |

## Deep Dives

- references/subdomain-discovery.md — Passive sources + CT logs, puredns/massdns resolution, alterx permutations, ASN→CIDR→PTR expansion, wildcard handling.
- references/attack-surface-mapping.md — httpx enrichment (`-td -favicon -jarm -asn`), katana headless/authenticated crawling, gau/wayback archive mining, JS endpoint + secret extraction, nuclei triage of the live set.
- references/subdomain-takeover.md — Dangling-DNS theory, can-i-take-over-xyz fingerprints, subzy/baddns/nuclei detection, the 2024-2025 deleted-S3 → CI/CD supply-chain pivot, NS-delegation takeover.
- references/cloud-saas-recon.md — cloud_enum multi-cloud, AADInternals/MicroBurst Azure tenant + blob recon (incl. the June-2025 Get-AADIntTenantDomains patch), GrayhatWarfare, GitHub/GitLab dorking with trufflehog/gitleaks/noseyparker.
- references/breach-credential-intel.md — theHarvester 4.x, HIBP API v3 (ALIEN TXTBASE), DeHashed, infostealer-log intel (Snowflake-style aged creds), username/email format derivation, password-pattern modeling.
- references/cve-exploit-intel.md — NVD 2.0 API + the 2026 selective-enrichment shift, EPSS v4, CISA KEV, Shodan InternetDB, searchsploit/nuclei, the KEV×EPSS×exposure prioritization stack.
