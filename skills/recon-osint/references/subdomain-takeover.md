# Subdomain Takeover & Dangling-DNS → Supply-Chain Pivot

Cluster: detecting and exploiting DNS records that point at deprovisioned third-party resources.
ATT&CK: T1583.001 (Acquire Infrastructure: Domains), T1584.001 (Compromise Infrastructure: Domains),
and the 2024-2025 escalation to T1195.002 (Supply Chain Compromise: Software). CWE-350 (Reliance on
Reverse DNS Resolution) / dangling-reference class.

## Theory / Mechanism

A subdomain takeover occurs when a DNS record (almost always a **CNAME**) still points at a
third-party service resource (S3 bucket, Heroku app, Azure App Service, Fastly service, etc.) that
has been *deleted/unclaimed*. Because the provider routes by `Host` header / resource name, an
attacker who re-creates a resource with the same name on that provider receives all traffic for the
dangling subdomain — enabling phishing on a trusted origin, cookie theft (same-site), OAuth redirect
abuse, and CSP bypass.

Detection is **fingerprint-based**: fetch the dangling host and compare the HTTP response against a
database of known "unclaimed resource" error strings maintained by the community
*can-i-take-over-xyz* project.

## Modern 2024-2026 Reality (verified)

- **can-i-take-over-xyz** currently tracks ~76 services; **nuclei** ships ~72 takeover templates.
  The repo has become as much a discussion board on per-service nuances as a fingerprint list.
- **CNAME dominates.** A/NS/MX/SRV takeovers are mostly theoretical now. The exception OWASP flags:
  **NS-record delegation** — a subdomain delegated to a third-party DNS provider whose account was
  closed can be reclaimed by anyone who registers a new account at that provider, giving control of
  *all* records under that subdomain.
- **GitHub Pages is now hardened**: it only serves `<username>.github.io`, so taking over
  `victim.github.io` requires registering the account named `victim`. Treat GH Pages as largely
  closed.
- **Cloud verification controls** reduce naive S3/Azure takeover: Azure App Service supports
  custom-domain TXT verification; keep the TXT after decommissioning to block reclaim.
- **The 2024-2025 escalation — deleted-S3 → supply-chain pivot (highest-impact new angle):**
  research from Oct-2024 to Jan-2025 found *deleted* S3 buckets still referenced by `<script src>`
  / asset URLs inside CI/CD pipelines and deployed apps. Re-registering the bucket name (S3 names
  are global, first-come) lets the attacker serve malicious JS that executes in the context of every
  downstream app that still references it — turning a "low" dangling reference into RCE-in-browser /
  build-pipeline compromise.

## Fingerprints (current high-signal services)

| Service | DNS clue | Body fingerprint (vulnerable) |
|---------|----------|-------------------------------|
| AWS S3 | CNAME → `*.s3*.amazonaws.com` | `NoSuchBucket` |
| Heroku | CNAME → `*.herokudns.com` | `No such app` |
| Fastly | CNAME → `*.fastly.net` | `Fastly error: unknown domain` |
| Azure (multi) | CNAME → `*.azurewebsites.net` / `*.cloudapp.azure.com` / `*.trafficmanager.net` | `404 Web Site not found` / NXDOMAIN on the target |
| Wix | CNAME → `*.wixdns.net` | `Error ConnectYourDomain occurred` / `wixErrorPagesApp` |
| Shopify | CNAME → `*.myshopify.com` | `Sorry, this shop is currently unavailable` |
| Bitbucket/Readme/Surge/etc | per can-i-take-over-xyz | per repo (verify live — statuses change) |

> Always re-verify against the live can-i-take-over-xyz repo: providers continually change reclaim
> policy, so a fingerprint that worked last quarter may be patched.

## Complete Working Detection + Validation

### 1. Multi-tool detection over the candidate list
```bash
# Fast first pass:
subzy run --targets all_subdomains.txt --concurrency 50 --hide_fails --output subzy.json
# Higher-accuracy second pass (handles cloud edge cases incl. Azure):
nuclei -l all_subdomains.txt -t http/takeovers/ -rl 120 -jsonl -o nuclei_takeover.jsonl
# baddns / Subdominator for cloud-specific coverage:
baddns -t all_subdomains.txt 2>/dev/null | tee baddns.txt
```

### 2. This skill's purpose-built checker (CNAME + fingerprint + NS-delegation)
```bash
python3 scripts/subdomain_takeover.py -l all_subdomains.txt -o takeovers.jsonl --threads 40
# Output JSONL: host, cname, service, fingerprint_matched, severity, ns_delegation
```

### 3. Hunt deleted-S3 references inside JS/HTML (supply-chain pivot)
```bash
# Collect every S3 reference from crawled JS/HTML (from attack-surface-mapping stage):
grep -rhoE 'https?://[a-z0-9.\-]+\.s3[.-][a-z0-9.\-]*amazonaws\.com[^"'"'"' )]*' js_out/ crawl.txt \
  | sed -E 's#https?://##; s#/.*##' | sort -u > s3_refs.txt
# For each referenced bucket, test if it is now unclaimed (HTTP 404 NoSuchBucket):
while read b; do
  body=$(curl -s --max-time 8 "https://$b/")
  echo "$body" | grep -q "NoSuchBucket" && echo "[CLAIMABLE] $b"
done < s3_refs.txt
# Claim test (authorized only): aws s3api create-bucket --bucket <name> --region <region>
# then serve a benign canary JS to PROVE impact — never serve real malicious payload in scope.
```

## Detection (defender side)

```yaml
# Sigma — newly-issued TLS cert for a host that recently went dangling (CT-log monitoring)
title: Possible Subdomain Takeover - New Cert on Dormant Host
id: f0a7c9b1-recon-takeover
status: experimental
logsource:
  product: ct_log        # certstream / Cloudflare CT firehose
detection:
  selection:
    domain|endswith: '.target.com'
  condition: selection and not in_known_inventory
level: high
tags: [attack.t1583.001, attack.resource_development]
```

Defender telemetry: dangling-DNS scanners (own assets) such as `dnsReaper`, periodic resolution of
all CNAMEs and alerting when the target resource returns a known "unclaimed" fingerprint; CT-log
monitoring for unexpected certs on subdomains; CDN/provider logs showing a new account claiming a
previously-org hostname. IOCs: 404/NoSuchBucket on an in-DNS host, sudden cert issuance, traffic to
a subdomain landing on a third-party origin.

## OPSEC

- **Touches:** a single HTTP GET per host to read the fingerprint (low noise). The *claim* itself
  is loud — it creates a resource in your attacker-controlled cloud/provider account and (for proof)
  may trigger CT-log cert issuance, which monitoring catches.
- **Cleanup:** for an authorized PoC, claim → serve a benign canary (unique string) to prove control
  → release the resource and document timestamps. Never leave the resource claimed past the report.
- **Evasion:** verify exploitability passively (DNS + fingerprint) before claiming; only claim when
  ROE explicitly permits, since claiming may interfere with other actors and is irreversible-ish for
  global-namespace resources (S3 names). For the S3 supply-chain variant, prove with a canary that is
  cosmetically inert — do not push code into a live downstream build.

## References

- HackerOne, "A Guide To Subdomain Takeovers 2.0" — https://www.hackerone.com/blog/guide-subdomain-takeovers-20
- OWASP WSTG, "Test for Subdomain Takeover" — https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover
- OWASP "Subdomain Takeover Prevention Cheat Sheet" — https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html
- "Subdomain Takeover in 2025 — New Methods + Tools" (deleted-S3 supply-chain research) — https://thehackerslog.substack.com/p/subdomain-takeover-in-2025-new-methods
- can-i-take-over-xyz — https://github.com/EdOverflow/can-i-take-over-xyz ; subzy, baddns, dnsReaper, Subdominator
