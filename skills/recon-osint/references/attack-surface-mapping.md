# Attack-Surface Mapping: Probing, Crawling & JS Secret Discovery

Cluster: turning a resolved name/IP list into a validated, enriched, crawlable attack surface, then
mining JavaScript and archives for endpoints and secrets. ATT&CK: T1595.002 (Active Scanning),
T1592.002 (Gather Victim Host Info: Software), T1593.003 (Search Open Websites/Domains: Code
Repositories / web content), T1552.001 (Unsecured Credentials: in files). CWE-200, CWE-540
(Inclusion of Sensitive Info in Source Code), CWE-615 (Info Exposure Through Comments).

## Theory / Mechanism

Modern recon in 2024-2026 is a *layered pipeline*: subdomain discovery → asset validation (httpx) →
crawling (katana) → historical URLs (gau/wayback) → JS analysis → template scanning (nuclei).
Ordering matters: if you validate first and only scan the live set you keep signal quality high and
noise low. Reverse the order and you mostly reverse the signal quality too.

The two highest-value layers are:

- **httpx** as the validation + enrichment layer: clusters live endpoints by technology, favicon
  hash, ASN, and JARM. Favicon hashes and JARM fingerprints let you correlate hosts that share a
  stack/origin even across different domains.
- **JavaScript analysis**: SPAs (React/Angular/Vue) no longer expose routes to a naive crawler.
  Real API endpoints, internal hostnames, cloud config, and hardcoded secrets live inside `.js`
  bundles. A crawler that cannot render JS / follow XHR/fetch produces an *illusion* of the surface.

## Modern 2024-2026 Tooling

- **httpx** enrichment flags: `-sc -title -td -favicon -jarm -asn -cdn` plus `-json` for diffable
  JSONL. `-td` = tech detection (Wappalyzer-style), `-favicon` = mmh3 hash for shodan pivots.
- **katana** is the SPA-aware crawler: `-jc` (JS crawl/parse), `-jsl` (output JS file links),
  `-kf all` (known-files: robots.txt, sitemap), `-hl`/`-headless` (Chrome render), `-fx` (extended
  scope), `-xhr` capture. Authenticated headless: point `-headless` at a Chrome remote-debugging
  port to crawl post-login routes (admin panels, tenant APIs).
- **gau** ("get all urls") aggregates archive sources: Wayback Machine, Common Crawl, AlienVault
  OTX, URLScan — surfaces deleted endpoints, old API versions, backups, debug pages.
- **nuclei** runs `exposures/`, `cves/`, `misconfiguration/`, `takeovers/` template families over
  the validated live set only (reduces noise).
- JS-secret tooling: **TruffleHog**, **gitleaks**, **nuclei -t exposures/tokens**, plus regex
  extraction of endpoints (`linkfinder`/`xnLinkFinder` patterns) — implemented in
  `scripts/js_secret_hunter.py`.

## Complete Working Commands

### 1. Validate + enrich (this gates everything downstream)
```bash
cat subs_resolved.txt | httpx \
  -sc -title -td -favicon -jarm -asn -cdn -ip -location \
  -rl 150 -timeout 8 -retries 1 \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0 Safari/537.36" \
  -json -o httpx_live.jsonl
jq -r 'select(.status_code) | .url' httpx_live.jsonl | sort -u > live_urls.txt
jq -r '.host + " " + (.a[]? // "")' httpx_live.jsonl | sort -u > ips.txt
```

### 2. Crawl (headless for SPAs) + harvest archive URLs
```bash
# Live crawl, depth 3 (deeper = exponential time), JS-aware:
katana -list live_urls.txt -d 3 -jc -jsl -kf all -fx -c 15 -silent -o crawl.txt
# SPA / heavy-JS targets: add headless render:
katana -list live_urls.txt -d 3 -headless -jc -jsl -c 10 -silent -o crawl_headless.txt
# Archived/forgotten URLs:
cat live_urls.txt | gau --threads 5 --subs > archive_urls.txt
# Interesting historical files:
grep -iE '\.(js|json|xml|ya?ml|config|env|bak|sql|tar\.gz|zip|log)(\?|$)' archive_urls.txt \
  | sort -u > interesting_archive.txt
```

### 3. Extract + scan JavaScript (endpoints + secrets)
```bash
# Collect all JS URLs from crawl + archive:
cat crawl.txt crawl_headless.txt archive_urls.txt | grep -iE '\.js(\?|$)' | sort -u > js_urls.txt
# Pull endpoints AND secrets in one pass:
python3 scripts/js_secret_hunter.py -l js_urls.txt -o js_out/
# Independent verification layer with nuclei exposure templates:
nuclei -l js_urls.txt -t http/exposures/ -t http/credentials/ -severity info,low,medium,high \
  -rl 100 -silent -o nuclei_js_exposures.txt
```

### 4. Triage the validated surface with nuclei
```bash
nuclei -l live_urls.txt \
  -t http/cves/ -t http/misconfiguration/ -t http/exposures/ -t http/takeovers/ \
  -severity medium,high,critical -rl 120 -c 25 -jsonl -o nuclei_findings.jsonl
```

### 5. Favicon / JARM pivot (find related infrastructure)
```bash
# mmh3 favicon hash → Shodan to find every host with the same favicon (often same org):
HASH=$(jq -r 'select(.favicon)|.favicon' httpx_live.jsonl | head -1)
shodan search "http.favicon.hash:$HASH" --fields ip_str,port,hostnames
```

## JavaScript Secret Patterns (what js_secret_hunter.py looks for)

| Provider | Regex (abridged) |
|----------|------------------|
| AWS Access Key | `(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}` |
| Google API | `AIza[0-9A-Za-z\-_]{35}` |
| Slack token | `xox[baprs]-[0-9A-Za-z-]{10,72}` |
| GitHub PAT | `gh[pousr]_[0-9A-Za-z]{36,}` |
| Stripe live | `sk_live_[0-9a-zA-Z]{24,}` |
| JWT | `eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+` |
| Private key | `-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----` |
| Generic API key | `(api[_-]?key|secret|token|passwd|password)["'\s:=]+[A-Za-z0-9_\-]{16,}` |

## Detection

```yaml
# Sigma — automated crawler / probing tool by User-Agent (web access logs)
title: Recon Tooling User-Agent in Web Access Logs
id: 9a1c44de-recon-ua
status: experimental
logsource:
  category: webserver
detection:
  selection:
    cs-user-agent|contains:
      - 'httpx'
      - 'katana'
      - 'nuclei'
      - 'ffuf'
      - 'gau'
      - 'Go-http-client'
  condition: selection
fields: [c-ip, cs-user-agent, cs-uri-stem, sc-status]
level: low
tags: [attack.reconnaissance, attack.t1595.002]
```

Additional telemetry: request-rate spikes from a single IP/ASN; sequential access to `.js`/`.map`
files (source-map disclosure); bursts of 404s consistent with content discovery; WAF anomaly on
favicon/JARM probe patterns. IOCs: default tool UAs, `Go-http-client/2.0`, rapid sequential JS
fetches, requests for `*.js.map`.

## OPSEC

- **Touches:** real HTTP(S) requests to the target — fully visible in access logs / WAF / CDN.
- **Cleanup:** nothing persists on target; purge any secrets you extract from your own loot store
  securely (they are live credentials and PII).
- **Evasion:** spoof a real browser UA, keep `-rl` low, route through a rotating proxy/cloud-egress
  pool, run the expensive headless + screenshot pass only over a *narrowed* list (it is slow and
  loud). Keep every stage in JSONL so you can diff re-runs and only re-feed *newly* discovered or
  newly authenticated hosts into the next stage.

## References

- HackTricks, "Pentesting Methodology" — https://hacktricks.wiki/en/generic-methodologies-and-resources/pentesting-methodology.html
- ProjectDiscovery, "Reconnaissance 104: Expanded Scanning" — https://projectdiscovery.io/blog/reconnaissance-series-4
- ProjectDiscovery katana — https://github.com/projectdiscovery/katana ; "A Deep Dive on Katana Field Extraction" — https://projectdiscovery.io/blog/a-deep-dive-on-katana-field-extraction
- "From Recon to Sensitive Key Exposure: Finding Leaked Secrets Using Nuclei, Subfinder, Katana & httpx" — medium.com/@mohamedsinger837
