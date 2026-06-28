# Cloud, SaaS & Source-Code Recon

Cluster: enumerating public cloud storage, identifying cloud tenancy (Azure/Entra), and mining
public source repos for secrets. ATT&CK: T1580 (Cloud Infrastructure Discovery), T1596.005 (Search
Open Technical DBs: Scan Databases), T1590.001 (Domain Properties), T1589 (Gather Victim Identity
Info), T1593.003 (Search Open Websites/Domains: Code Repositories), T1213.003 (Data from
Code Repositories). CWE-732 (Incorrect Permission Assignment), CWE-540 (Secrets in Source).

## Theory / Mechanism

Three sub-surfaces, all reachable *without* touching the target's own infrastructure:

1. **Public cloud storage** — buckets/blobs are addressed by globally-unique names in predictable
   namespaces (`<name>.s3.amazonaws.com`, `<name>.blob.core.windows.net`,
   `storage.googleapis.com/<name>`). Enumeration = mutate the org name and probe DNS/HTTP.
2. **Cloud tenancy / identity** — Microsoft does not treat tenant IDs as secret; unauthenticated
   endpoints (`getuserrealm`, OpenID config) reveal whether a domain is cloud-managed or federated,
   the tenant GUID, and federation/SSO type — all invisible to the tenant's sign-in logs.
3. **Source code** — developers and third-party vendors leak `.env`, keys, and connection strings
   into public GitHub/GitLab. The `org:` search operator + secret scanners surface them.

## Modern 2024-2026 Tooling & Notable Changes (verified)

- **cloud_enum** (initstring) — multi-cloud OSINT over AWS/Azure/GCP from one or more keywords
  (`-k`), mutated via `enum_tools/fuzz.txt` (`-m` custom mutations, `-b` brute file for Azure
  containers / GCP functions). Now uses `uv` for deps.
- **S3Scanner / bucket_finder / AWS Eye** for S3; **GrayhatWarfare** is a search engine for already-
  open S3 buckets, Azure blobs, and GCS objects.
- **AADInternals** — outsider Azure recon: `Invoke-AADIntReconAsOutsider -Domain company.com`.
  **IMPORTANT 2025 patch:** `Get-AADIntTenantDomains` relied on Exchange `Get-FederationInformation`
  which previously returned *all* accepted domains unauthenticated. **Microsoft patched this in
  mid-June 2025** — the field now only echoes the single domain you queried. Multi-domain
  enumeration via that path is dead; fall back to probing each suspected domain via the OpenID/
  getuserrealm endpoint. **ROADtools** and **Stormspotter** map authenticated tenant graphs.
- **MicroBurst** — `Invoke-EnumerateAzureBlobs -Base <name>` for blob name-permutation enum.
- Secret scanning: **TruffleHog v3** (verification-first — live-validates the credential),
  **gitleaks v8** (regex/entropy, fast pre-commit, SARIF), **Nosey Parker** (high-throughput +
  Explorer UI). GitGuardian's 2025 report counted 23M+ new secrets on public GitHub (+25% YoY).

## Complete Working Commands

### 1. Multi-cloud storage enumeration
```bash
# Build mutations from the org name + brand variants:
printf 'target\ntarget-dev\ntarget-staging\ntarget-prod\ntarget-backup\ntarget-logs\ntargetcorp\n' > muts.txt
cloud_enum -k target -k targetcorp -m muts.txt -b /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -t 10 -l cloud_enum.log
# Targeted S3:
s3scanner scan --bucket-file s3_candidates.txt --enumerate
# Already-public buckets/blobs via GrayhatWarfare API:
curl -s "https://buckets.grayhatwarfare.com/api/v2/buckets?keywords=target" \
  -H "Authorization: Bearer $GHW_API_KEY" | jq '.buckets[] | {bucket, fileCount}'
# Manual unauth listing (S3 anonymous):
aws s3 ls s3://target-backup --no-sign-request 2>/dev/null
```

### 2. Azure / Entra outsider recon (PowerShell)
```powershell
Import-Module AADInternals
# Managed vs federated, tenant brand/GUID, MX/SPF, DKIM, MDI:
Invoke-AADIntReconAsOutsider -Domain "target.com" | Format-Table
# Per-domain realm probe (the supported path after the June-2025 patch):
Invoke-AADIntUserRealmV2 -UserName "[email protected]"
# Blob name permutation enum:
Import-Module .\MicroBurst.psm1
Invoke-EnumerateAzureBlobs -Base target
```
```bash
# Pure-bash equivalents (no PowerShell needed):
curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=user@target.com&xml=1"
curl -s "https://login.microsoftonline.com/target.com/.well-known/openid-configuration" \
  | jq '{issuer, token_endpoint, tenant_region_scope}'
# Tenant GUID from issuer:
curl -s "https://login.microsoftonline.com/target.com/v2.0/.well-known/openid-configuration" \
  | jq -r '.issuer' | grep -oE '[0-9a-f-]{36}'
```

### 3. GCP / Firebase quick checks
```bash
curl -s "https://storage.googleapis.com/target"            # GCS bucket listing if open
curl -s "https://target.firebaseio.com/.json"              # open Firebase RTDB
curl -s "https://target-default-rtdb.firebaseio.com/.json"
```

### 4. GitHub / GitLab dorking + secret scanning
```bash
# Org-wide live-verified secret scan (issues/PRs/gists/wikis too):
trufflehog github --org=targetcorp --results=verified \
  --include-wikis --issue-comments --pr-comments --gist-comments
# Full git-history regex/entropy scan over locally-cloned repos:
gitleaks detect --source=./repos --report-format=sarif --report-path=gitleaks.sarif
# High-throughput scan + triage UI:
noseyparker scan --datastore np.db ./repos && noseyparker report --datastore np.db
# Manual high-signal dorks (Web UI; legacy code-search API has no regex):
#   org:targetcorp filename:.env
#   org:targetcorp "BEGIN RSA PRIVATE KEY"
#   org:targetcorp AKIA                      (AWS key prefix)
#   org:targetcorp "jdbc:" OR "mongodb://" OR "redis://"
#   org:targetcorp filename:terraform.tfvars NOT example NOT test NOT sample
# Persistent leaks even after repo went private/deleted (Google-indexed raw):
#   site:raw.githubusercontent.com targetcorp "api_key"
```

### 5. This skill's combined cloud+code enumerator
```bash
python3 scripts/cloud_asset_enum.py -k target --company targetcorp \
  --azure-domain target.com --gh-org targetcorp --gh-token "$GH_TOKEN" -o cloud_out/
```

## Detection

```yaml
# Sigma — anonymous / cross-account S3 enumeration against own buckets (CloudTrail)
title: Anonymous S3 Bucket Enumeration
id: 3f5b81aa-recon-s3enum
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 's3.amazonaws.com'
    eventName:
      - 'ListBucket'
      - 'GetBucketAcl'
      - 'HeadBucket'
    userIdentity.type: 'AWSAccount'         # or 'Anonymous'
  filter_known:
    userIdentity.accountId: '<your-account-id>'
  condition: selection and not filter_known
level: medium
tags: [attack.t1580, attack.t1619, attack.reconnaissance]
```

Defender telemetry: CloudTrail `ListBucket`/`GetObject` from anonymous or foreign principals;
Azure: unauth `getuserrealm`/OpenID probes are **not** in Entra sign-in logs (blind spot — defend by
treating tenant data as public and hardening domain-verification TXT); GitHub: org audit log
(only members' actions) + native secret-scanning alerts; GuardDuty `Discovery:S3/*`. IOCs: bucket
404/AccessDenied probe bursts, `cloud_enum`/`MicroBurst` UA patterns, mass GitHub code-search from a
single token.

## OPSEC

- **Touches:** cloud-storage probes hit the *provider*, not the target — but are still rate-limited
  and logged in the resource owner's CloudTrail/storage logs. Scope-discipline: a found blob/bucket
  may not belong to your target — verify ownership before reporting.
- **Azure recon is the stealthiest** sub-surface (unauth, invisible to the tenant).
- **GitHub:** use a throwaway PAT, respect rate limits to avoid token bans; org members' searches
  appear in the org audit log.
- **Cleanup / handling:** discovered secrets are live credentials + PII — store encrypted, scope
  their use to ROE, and never test them against production beyond what authorization allows.

## References

- initstring/cloud_enum — https://github.com/initstring/cloud_enum
- "Azure Tenant Discovery & Reconnaissance — A Practical Guide for External Testers" — medium.com/@tareshsharma17
- AADInternals June-2025 domain-enum patch (Get-AADIntTenantDomains) — https://blog.jacobh.io/posts/azure_external_enumeration/ and InternalAllTheThings Azure enumeration
- HackTricks, "Github Dorks & Leaks" — https://hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/github-leaked-secrets.html
- GitGuardian, "2025 State of Secrets Sprawl" (23M+ new secrets) ; TruffleHog — github.com/trufflesecurity/trufflehog ; gitleaks — github.com/gitleaks/gitleaks ; Nosey Parker — github.com/praetorian-inc/noseyparker
