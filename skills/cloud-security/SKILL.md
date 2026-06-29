---
name: cloud-security
description: Use when attacking AWS/Azure/GCP cloud — IAM/identity privilege escalation, IMDS/metadata SSRF, Entra device-code & PRT theft, GCP impersonation chains, Kubernetes/container escape, IaC/CI-CD federation abuse
metadata:
  type: offensive
  phase: exploitation
  tools: pacu, cloudfox, scoutsuite, prowler, trivy, kubectl, aws-cli, az-cli, gcloud, peirates, mkat, azurehound, roadtools, stratus-red-team, kube-bench
  mitre: [T1078.004, T1552.005, T1098.001, T1528, T1611, T1548]
kill_chain:
  phase: [recon, exploit]
  step: [1, 4]
  attck_tactics: [TA0043, TA0001, TA0004, TA0008, TA0006]
  attck_techniques: [T1078.004, T1552.005, T1552.007, T1098.001, T1098.003, T1528, T1606.002, T1611, T1610, T1134.001, T1548, T1538]
depends_on: [recon-osint]
feeds_into: [exploit-development, active-directory-attack, advanced-redteam]
inputs: [cloud_config, iam_policies, kubeconfig, ci_cd_config]
outputs: [cloud_misconfig_list, finding_record, attack_path, stolen_credentials]
references:
  - references/aws-iam-privesc.md
  - references/imds-metadata-ssrf.md
  - references/azure-entra-attacks.md
  - references/gcp-attacks.md
  - references/kubernetes-container-escape.md
  - references/iac-secrets-ci-cd.md
scripts:
  - scripts/aws_privesc_enum.py
  - scripts/imds_harvester.py
  - scripts/entra_device_code_phish.py
  - scripts/gcp_impersonation_mapper.py
  - scripts/k8s_can_i_abuse.py
  - scripts/oidc_trust_auditor.py
---

# Cloud Security & Attack

## When to Activate

- Cloud penetration test / red team against AWS, Azure (Entra ID), or GCP
- IAM / identity privilege escalation and cross-account or cross-tenant pivoting
- Compromised web app or SSRF reachable from cloud compute — harvest metadata credentials
- Kubernetes / container assessment, node breakout, cluster takeover
- CI/CD and IaC review: Terraform state, OIDC federation trust policies, pipeline secrets
- Post-exploitation: secret extraction, lateral movement, persistence in cloud control plane

## Technique Map

| Technique | ATT&CK | CWE | Reference | Script |
|-----------|--------|-----|-----------|--------|
| AWS IAM privesc (CreatePolicyVersion, PassRole, AttachPolicy) | T1098.001 | CWE-269 | references/aws-iam-privesc.md | scripts/aws_privesc_enum.py |
| AWS `sts:AssumeRoot` member-account escalation | T1078.004 | CWE-269 | references/aws-iam-privesc.md | scripts/aws_privesc_enum.py |
| Cross-account confused deputy / missing ExternalId | T1078.004 | CWE-441 | references/aws-iam-privesc.md | scripts/oidc_trust_auditor.py |
| IMDS / metadata SSRF credential theft (AWS/Azure/GCP) | T1552.005 | CWE-918 | references/imds-metadata-ssrf.md | scripts/imds_harvester.py |
| EKS node creds → IRSA / Pod Identity pivot | T1552.007 | CWE-668 | references/imds-metadata-ssrf.md | scripts/imds_harvester.py |
| Entra device-code phishing → PRT / device join | T1528 | CWE-287 | references/azure-entra-attacks.md | scripts/entra_device_code_phish.py |
| FOCI refresh-token family abuse | T1550.001 | CWE-613 | references/azure-entra-attacks.md | scripts/entra_device_code_phish.py |
| Azure Managed Identity / App-Admin → SP escalation | T1098.001 | CWE-269 | references/azure-entra-attacks.md | scripts/imds_harvester.py |
| GCP `actAs` + resource create impersonation chain | T1078.004 | CWE-269 | references/gcp-attacks.md | scripts/gcp_impersonation_mapper.py |
| GCP `serviceAccountTokenCreator` token chains | T1528 | CWE-269 | references/gcp-attacks.md | scripts/gcp_impersonation_mapper.py |
| Vertex AI P4SA / Ray head-node escalation | T1078.004 | CWE-732 | references/gcp-attacks.md | scripts/gcp_impersonation_mapper.py |
| Container escape (runc Leaky Vessels CVE-2024-21626) | T1611 | CWE-668 | references/kubernetes-container-escape.md | - |
| IngressNightmare (CVE-2025-1974) cluster takeover | T1190 | CWE-94 | references/kubernetes-container-escape.md | scripts/k8s_can_i_abuse.py |
| K8s RBAC privesc (pods/exec, token mount, node proxy) | T1078 | CWE-269 | references/kubernetes-container-escape.md | scripts/k8s_can_i_abuse.py |
| Terraform state secret extraction | T1552.001 | CWE-312 | references/iac-secrets-ci-cd.md | scripts/oidc_trust_auditor.py |
| OIDC federation trust-policy abuse (GitHub/TF Cloud) | T1199 | CWE-441 | references/iac-secrets-ci-cd.md | scripts/oidc_trust_auditor.py |

## Quick Start

```bash
# --- 0. Identify where you are ---
aws sts get-caller-identity                       # AWS
az account show && az ad signed-in-user show      # Azure
gcloud auth list && gcloud config get-value project  # GCP

# --- 1. AWS: enumerate then map privesc paths ---
python3 scripts/aws_privesc_enum.py --profile compromised --json paths.json
cloudfox aws --profile compromised all-checks      # alt: broad inventory
pacu  # > run iam__enum_permissions ; run iam__privesc_scan

# --- 2. SSRF / metadata: harvest creds from a reachable compute target ---
python3 scripts/imds_harvester.py --ssrf "https://app/fetch?url=" --provider aws
python3 scripts/imds_harvester.py --local --provider azure --resource https://vault.azure.net/

# --- 3. Azure Entra: device-code phish for tokens (authorized phishing only) ---
python3 scripts/entra_device_code_phish.py --resource https://graph.microsoft.com \
    --client-id 29d9ed98-a469-4536-ade2-f981bc1d605e   # Auth Broker -> PRT path

# --- 4. GCP: build the service-account impersonation graph ---
python3 scripts/gcp_impersonation_mapper.py --project TARGET --out gcp_graph.json

# --- 5. Kubernetes: what can this token do, and can we break out? ---
python3 scripts/k8s_can_i_abuse.py --kubeconfig ./kubeconfig
kubectl auth can-i --list ; peirates

# --- 6. CI/CD + IaC: audit federation trust + dump state secrets ---
python3 scripts/oidc_trust_auditor.py --profile compromised
aws s3 cp s3://tf-state/prod/terraform.tfstate - | jq '.. | .password? // empty'
```

## OPSEC & Detection (summary)

| Technique | Telemetry / IOC | Detection (Sigma / EDR / cloud) | OPSEC note |
|-----------|-----------------|---------------------------------|------------|
| IAM privesc API calls | CloudTrail `CreatePolicyVersion`, `AttachUserPolicy`, `CreateLoginProfile` | Alert on IAM write by non-IAM-admin principal; GuardDuty `PrivilegeEscalation:IAMUser/*` | Use existing admin sessions; avoid bulk enum that trips anomaly detection |
| `sts:AssumeRoot` | CloudTrail `AssumeRoot` (regional only) | Elastic "AssumeRoot by Rare User and Member Account" (new-terms rule) | Rare-event detection fires on first use per (principal, member account) |
| IMDS SSRF | VPC flow to 169.254.169.254 from web tier; STS use from new ASN | GuardDuty `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration*` (creds used off-instance) | Use creds from same egress IP where possible; creds expire — refresh fast |
| Entra device-code phish | Sign-in logs `authenticationProtocol=deviceCode`; Auth Broker client `29d9ed98-...`; new device registration | Sentinel device-code anomaly; CA "block device code flow" | Tokens valid even after password reset; device-join = MFA-resistant persistence |
| GCP impersonation | `GenerateAccessToken` / `generateAccessToken` in Admin Activity + Data Access logs | Alert on impersonation by principal lacking a documented chain | Requires Data Access (`DATA_READ`) audit logs enabled to see token minting |
| Container escape (runc) | New process from `/proc/self/fd/*` cwd; host binary writes; `nsenter` in container | Falco `Container escape`/`Drop and execute new binary`; runc ≤1.1.11 inventory | Overwrites host runc → noisy; prefer read-only host FS read for stealth |
| IngressNightmare | NGINX ingress pod loads `.so` from `/proc`; outbound from controller | Falco/Sysdig "IngressNightmare" shared-lib load; ingress-nginx < 1.11.5/1.12.1 | Exploit hits admission webhook (often internal-only) — low external noise |
| OIDC trust abuse | CloudTrail `AssumeRoleWithWebIdentity` from unexpected `sub`/repo | Alert on web-identity assume with mismatched `aud`/`sub`; RCP block | Wildcard `sub` (`org:foo*`) still exploitable; no creds needed |

## Deep Dives

- **references/aws-iam-privesc.md** — Classic + 2024 IAM escalation chains, `sts:AssumeRoot`, cross-account confused deputy / ExternalId, Cognito, secrets harvesting; detection per API.
- **references/imds-metadata-ssrf.md** — IMDSv1/v2 mechanics, SSRF bypasses, Azure & GCP metadata token theft, EKS node-cred → IRSA/Pod Identity lateral movement.
- **references/azure-entra-attacks.md** — Storm-2372 device-code → PRT → device-join chain, FOCI token families, Managed Identity abuse, Application Administrator → service principal → Global Admin.
- **references/gcp-attacks.md** — `actAs` + resource-create impersonation, `serviceAccountTokenCreator` chains, Cloud Functions takeover, Vertex AI ModeLeak/P4SA/Ray escalation.
- **references/kubernetes-container-escape.md** — runc Leaky Vessels (CVE-2024-21626), privileged/hostPID/Docker-socket escapes, IngressNightmare (CVE-2025-1974), RBAC primitives, kubelet/etcd.
- **references/iac-secrets-ci-cd.md** — Terraform state secret extraction, OIDC federation trust-policy abuse (GitHub Actions / Terraform Cloud), pipeline secret theft, RCP/SCP defenses.
