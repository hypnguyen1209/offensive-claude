# Subdomain Discovery & DNS Asset Expansion

Cluster: passive + active subdomain enumeration, DNS resolution, permutation, and ASN/CIDR-based
expansion. ATT&CK: T1590.002 (Gather Victim Network Info: DNS), T1595.002 (Active Scanning:
Vuln/Surface), T1590.005 (IP Addresses), T1596.001/.005 (Search Open Technical DBs: DNS / Scan DBs).
CWE-200 (Information Exposure).

## Theory / Mechanism

Subdomains are discovered through three orthogonal pipelines that must be combined for coverage:

1. **Passive** — query third-party data that already observed the names: certificate-transparency
   (CT) logs, passive-DNS aggregators (SecurityTrails, VirusTotal, Chaos), search-engine indexes,
   and threat-intel feeds. Zero packets to the target. CT logs are the single highest-yield source
   because every publicly-trusted TLS cert is logged (RFC 6962) and indexed by crt.sh / Censys.
2. **Active brute / permutation** — generate candidate labels (wordlist + permutations) and resolve
   them. This *does* touch DNS infrastructure and is detectable.
3. **Infrastructure expansion** — pivot from a known IP to its ASN, derive the org's CIDR ranges,
   then reverse-resolve (PTR) and vhost-fuzz to find names DNS enumeration alone misses.

**Critical methodology rule (commonly gotten wrong):** never pipe raw enumeration output straight
into `httpx`. First DNS-resolve through `puredns`/`shuffledns` with a validated resolver list to
strip wildcard/false-positive entries; otherwise your live-host set is polluted.

## Modern 2024-2026 Tooling Landscape

The ProjectDiscovery suite is now the de-facto standard. Key shifts since the old single-file skill:

- **subfinder** is the passive primary; configure API keys in
  `~/.config/subfinder/provider-config.yaml` and use `-all`. The **Chaos** DB is now public (no
  invite). crt.sh tightened rate limits, so cache CT results.
- **puredns** replaced `shuffledns` for most brute/resolve work (better wildcard + DNS-poison
  filtering) but requires **massdns** + a *validated* resolver list.
- **alterx** is the modern replacement for `altdns`; **gotator** is an alternative permutation
  engine.
- **dnsx** handles flexible probing and `-ptr` reverse lookups; **mapcidr** expands CIDRs.
- **amass v4** is slowest but builds a DNS-topology graph and occasionally finds names others miss
  on large scopes — run it overnight for high-value targets only.

## Complete Working Commands

### 1. Validate resolvers (do this first, reuse the file)
```bash
# Bad resolvers cause massive false positives; validate once.
dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 100 -o resolvers.txt
# Or use puredns' own healthcheck against a trusted seed:
puredns resolve /dev/null -r resolvers.txt --quiet   # exits if resolvers unhealthy
```

### 2. Passive enumeration (stealth, zero target traffic)
```bash
DOMAIN=target.com
subfinder -d $DOMAIN -all -silent -o subs_subfinder.txt
amass enum -passive -d $DOMAIN -silent -o subs_amass.txt           # optional, slow
# CT logs directly (cache to avoid crt.sh rate limits):
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" \
  | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > subs_crtsh.txt
# Chaos public dataset (ProjectDiscovery):
chaos -d $DOMAIN -silent >> subs_chaos.txt 2>/dev/null
cat subs_*.txt | sort -u > subs_passive.txt
```

### 3. Active brute + permutation, then RESOLVE (filters wildcards)
```bash
# Brute-force with a quality wordlist (n0kovo/best-dns-wordlist, SecLists DNS):
puredns bruteforce /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt $DOMAIN \
  -r resolvers.txt --rate-limit 1500 -w subs_brute.txt

# Permutations from what we already know (find api-us-east-1 → guess api-eu-west-1):
alterx -l subs_passive.txt -enrich -silent > perms.txt
puredns resolve perms.txt -r resolvers.txt --rate-limit 1500 -w subs_perm.txt

# Final authoritative resolve of EVERYTHING (this is the gate before httpx):
cat subs_passive.txt subs_brute.txt subs_perm.txt | sort -u > subs_all_candidates.txt
puredns resolve subs_all_candidates.txt -r resolvers.txt --rate-limit 1500 -w subs_resolved.txt
```

### 4. ASN → CIDR → reverse-DNS expansion (underused, high yield)
```bash
# Find the org's ASN(s) from a known IP or org name:
IP=$(dig +short $DOMAIN | head -1)
asnmap -i $IP -silent              # → ASNxxxx
# Or by org name:
asnmap -org "TARGET ORG" -silent

# Expand ASN → CIDR ranges → individual IPs → PTR records:
asnmap -a AS12345 -silent | mapcidr -silent | dnsx -ptr -resp-only -silent > ptr_names.txt
# vhost fuzz an IP that serves many names:
ffuf -u https://$IP/ -H "Host: FUZZ.$DOMAIN" \
  -w subs_resolved.txt -mc 200,301,302,403 -ac -of csv -o vhosts.csv
```

### 5. NSEC/NSEC3 zone walking (DNSSEC misconfig)
```bash
# If the zone is DNSSEC-signed with NSEC, the whole zone can be walked:
ldns-walk @ns1.target.com target.com
# NSEC3 (hashed) — collect then crack hashes:
nsec3walker target.com   # then nsec3map / hashcat the collected hashes
```

## Wildcard Handling

Wildcard DNS (`*.target.com` → one IP) makes every brute-forced label resolve, producing thousands
of junk hits. `puredns` auto-detects wildcards by resolving random labels and filtering matches.
Manually verify: `dig $(openssl rand -hex 8).$DOMAIN` — if it returns an A record, a wildcard exists
and you MUST resolve through puredns (not plain `dnsx -a`) to filter it.

## Detection

Active brute-forcing is the noisy part. Defenders detect it via DNS-query telemetry:

```yaml
# Sigma — high-volume distinct-subdomain (DNS brute) from a single source
title: DNS Subdomain Brute-Force Enumeration
id: 6c3a2f10-recon-dnsbrute
status: experimental
logsource:
  category: dns
  product: zeek          # or Windows DNS Analytical / Cloudflare GW logs
detection:
  selection:
    query_type: 'A'
  timeframe: 1m
  condition: selection | count(distinct query) by src_ip > 200
  filter_nxdomain:        # a brute generates a high NXDOMAIN ratio
    rcode: 'NXDOMAIN'
fields: [src_ip, query, rcode]
level: medium
tags: [attack.reconnaissance, attack.t1590.002]
```

EDR/NDR telemetry to watch: spike in distinct DNS labels per source IP, high NXDOMAIN ratio
(>40% in a window), and PTR sweeps across a CIDR. CT-log monitoring (certstream) only reveals
*new* certificates — it cannot detect passive enumeration of existing names. IOCs: tool-default
User-Agents leaking into HTTP fallbacks (`subfinder`, `amass`), and resolver bursts to
`8.8.8.8`/`1.1.1.1` from a scanning host.

## OPSEC

- **Touches:** passive sources touch only third parties (invisible to target). Brute/resolve and
  PTR sweeps touch authoritative NS + public resolvers and are logged.
- **Cleanup:** none on target for passive; nothing to clean for resolution beyond not persisting
  PII-laden output insecurely.
- **Evasion:** rotate resolvers, cap `--rate-limit`, never brute a single authoritative NS directly
  (route through public resolvers so load is distributed). Prefer passive-only for the stealthiest
  phase; escalate to active only when scope/ROE permits noise. Diversify sources — no single tool
  finds everything.

## References

- ProjectDiscovery, "Reconnaissance 102: Subdomain Enumeration" — https://projectdiscovery.io/blog/recon-series-2
- "Subdomain Enumeration in 2026: Tools, Techniques, and What Actually Works" — https://dev.to/kai_learner/subdomain-enumeration-in-2026-tools-techniques-and-what-actually-works-1en0
- uprootsecurity, "The best Subdomain enumeration techniques guide" — https://www.uprootsecurity.com/blog/the-best-subdomain-enumeration-techniques-guide
- puredns / massdns, alterx, asnmap, mapcidr, dnsx — github.com/projectdiscovery, github.com/d3mondev/puredns
