# Cloud & Identity Hunting — Entra ID OAuth/Device-Code, PRT Theft, CloudTrail

## Theory / Mechanism

Identity is the new perimeter. Cloud attacks increasingly avoid malware entirely: they
abuse *legitimate* OAuth flows to steal tokens, so from the IdP's view "everything is
normal." That is precisely why these require proactive **hunting**, not just alerting — the
control plane logs (Entra sign-ins, Microsoft Graph audit, AWS CloudTrail) are the only
telemetry, and the malicious events look identical to benign ones at the field level. You
hunt the *context*: which app, from which ASN/geo, under which conditional-access decision,
followed by what API behavior.

## Entra ID device-code phishing (T1528 / T1566, CWE-287)

Device-code phishing abuses the OAuth 2.0 **Device Authorization Grant**. The attacker
initiates a device-code flow, sends the victim a *real* `microsoft.com/devicelogin` page +
real code; the victim authenticates and completes MFA; the **refresh/access tokens land on
the attacker's machine**. No infrastructure, MFA is co-opted not bypassed, and access
survives password resets.

**Active campaigns (verified):**
- **STORM-2372** (Russia-aligned, MSTIC, Feb 2025) — device-code phishing of M365 accounts.
- **Device-code vishing** (BleepingComputer, 2025) — voice-driven lures.
- **KnowBe4 campaign** (first seen Dec 2025) — email/web lures (fake payment config,
  doc-share, voicemail) delivering device-code attacks.
- **Tycoon 2FA** PhaaS operators adopted device-code phishing (eSentire, 2025).
- **EvilTokens** PhaaS launched on Telegram **Feb 16, 2026** — tiered email/token/SMTP-relay
  service with AI-assisted lure tailoring.
- **FIDO downgrade** (2025) — trick Entra into requesting weaker auth (password+SMS) instead
  of FIDO2, then AiTM-phish the weaker channel.

**Hunt signals (Entra `SigninLogs`):**

```kql
// 1) Device-code sign-ins from never-before-seen source for that user
SigninLogs
| where TimeGenerated > ago(14d)
| where AuthenticationProtocol == "deviceCode" and ResultType == 0
| extend asn = tostring(parse_json(tostring(AutonomousSystemNumber)))
| summarize first_seen = min(TimeGenerated), asns = make_set(AutonomousSystemNumber),
            ips = make_set(IPAddress), cities = make_set(tostring(LocationDetails.city))
        by UserPrincipalName, AppDisplayName, AppId
| where first_seen > ago(7d)          // newly appearing device-code usage
| order by first_seen desc
```

Key app IDs to monitor:
- `29d9ed98-a469-4536-ade2-f981bc1d605e` — Microsoft Authentication Broker (impersonated).
- `4765445b-32c6-49b0-83e6-1d93765276ca` — OfficeHome (credential-relay variant).

```kql
// 2) Post-compromise Graph enumeration shortly after a device-code sign-in (session reuse)
let dc = SigninLogs
  | where AuthenticationProtocol == "deviceCode" and ResultType == 0
  | project UserPrincipalName, CorrelationId, IPAddress, t0 = TimeGenerated;
MicrosoftGraphActivityLogs
| where RequestUri has_any ("/messages", "/drive", "/contacts", "/users", "/me/")
| join kind=inner dc on $left.UserId == $right.UserPrincipalName
| where TimeGenerated between (t0 .. t0 + 1h)
| summarize calls = count(), uris = make_set(RequestUri, 20) by UserPrincipalName, IPAddress
| where calls > 50          // mass mailbox/OneDrive/contact reads = harvesting
```

Also hunt: **device registration** against the tenant from the token (persistence that
survives token revocation), and malicious **inbox rules** (auto-forward external / move to
RSS Feeds / auto-delete) created right after a device-code sign-in.

Elastic Security Labs open-sourced ready rules: *Entra ID Session Reuse with Suspicious
Graph Access*, *OAuth Phishing via Visual Studio Code Client*, *Suspicious Microsoft OAuth
Flow via Auth Broker to DRS*, *Suspicious ADRS Token Request by Microsoft Auth Broker* —
adapt their logic to your SIEM.

## Illicit OAuth consent grants (T1528, CWE-862)

Beyond device-code, attackers register/abuse OAuth apps and phish *consent* for Graph
scopes (mail.read, files.readwrite.all). Hunt the consent + app-credential events:

```kql
// Risky consent grant or new app credential (possible OAuth persistence)
AuditLogs
| where OperationName in ("Consent to application", "Add app role assignment grant to user",
                          "Add service principal credentials", "Update application - Certificates and secrets management")
| extend scope = tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[0].newValue)
| where scope has_any ("Mail.Read","Mail.ReadWrite","Files.ReadWrite.All","Directory.Read.All",
                        "User.Read.All","full_access_as_app","offline_access")
| project TimeGenerated, OperationName, InitiatedBy, AppId = tostring(TargetResources[0].id), scope
```

Defenses to verify during the hunt: admin-consent workflow enforced (users cannot self-grant
Graph scopes); Conditional Access requiring compliant/Hybrid-joined device (attacker host
fails compliance even with a stolen token). Response: **revoke sessions** (Users → Revoke
sessions) for non-CAE workloads to kill cached tokens.

## Primary Refresh Token (PRT) theft (T1550.001, CWE-522)

The PRT is the device-bound SSO credential. Theft (via tooling like ROADtoken, or
LSASS/CloudAP extraction) yields broad SSO. Hunt for anomalous PRT-backed sign-ins and the
on-host extraction:

- Sign-ins with `AuthenticationProtocol == "primaryRefreshToken"` from an IP/geo that does
  not match the device's normal pattern.
- On-host: access to `cloudAP`/`Microsoft Passport` keys, `dsregcmd /status` recon,
  LSASS access (see `windows-endpoint-hunting.md`).
- Conditional-access *satisfied* by a device claim that does not match the sign-in IP.

```kql
SigninLogs
| where AuthenticationProtocol == "primaryRefreshToken"
| summarize geos = make_set(tostring(LocationDetails.countryOrRegion)),
            ips = make_set(IPAddress), devices = make_set(DeviceDetail.deviceId)
        by UserPrincipalName, bin(TimeGenerated, 1d)
| where array_length(geos) > 1     // PRT used from multiple countries same day -> theft/replay
```

## AWS / multi-cloud control-plane hunting (T1078.004, T1098, CWE-269)

CloudTrail is the AWS analog of Entra audit logs. High-value hunts:

- **STS abuse**: `AssumeRole` from an external/unusual account or `GetSessionToken` followed
  by privilege enumeration.
- **Persistence**: `CreateAccessKey`/`CreateLoginProfile`/`UpdateLoginProfile` on another
  user; `CreateUser` + `AttachUserPolicy AdministratorAccess`.
- **Defense evasion**: `StopLogging`/`DeleteTrail` on CloudTrail, `DeleteFlowLogs`.
- **Enumeration bursts**: many `Describe*`/`List*`/`GetCallerIdentity` from one principal in
  a short window (recon after creds compromise).

```python
# scripts/cloudtrail_hunt.py runs these as offline analytics over CloudTrail JSON.
# Example detection logic (also see the script):
#   group events by (userIdentity.arn, sourceIPAddress) in 10-min bins;
#   flag bins with >N distinct Describe*/List* events  -> recon burst
#   flag any StopLogging/DeleteTrail/DeleteFlowLogs     -> log tampering (CRITICAL)
#   flag CreateAccessKey where target user != caller    -> credential persistence
```

```sql
-- Athena over CloudTrail: CloudTrail tampering (defense evasion)
SELECT eventtime, useridentity.arn, sourceipaddress, eventname
FROM cloudtrail_logs
WHERE eventname IN ('StopLogging','DeleteTrail','UpdateTrail','DeleteFlowLogs','PutEventSelectors')
  AND eventtime > date_add('day', -7, now())
ORDER BY eventtime DESC;
```

## Detection summary

| Behavior | Telemetry / IOC | Detection |
|----------|-----------------|-----------|
| Device-code phish | `deviceCode` sign-in, AppId broker/OfficeHome, new ASN | KQL #1 + Graph-enum join #2 |
| OAuth consent abuse | "Consent to application", high-risk scopes | AuditLogs consent hunt |
| PRT theft | `primaryRefreshToken` from multi-geo; LSASS/cloudAP access | PRT KQL + endpoint join |
| AWS recon/persist | Describe* burst, CreateAccessKey on other user | cloudtrail_hunt.py |
| Log tampering | StopLogging/DeleteTrail/DeleteFlowLogs | Athena query (critical) |

## OPSEC (analyst)

- Not every device-code sign-in is malicious — first **baseline** which apps legitimately
  use device-code, from where, under which CA decisions, or you will flood the SOC.
- These attacks leave *no endpoint malware*; the only evidence is control-plane logs. Ensure
  Entra sign-in/audit + Graph activity logs and CloudTrail (all regions, org trail) are
  retained ≥ 90 days *before* you need to hunt — attackers disable logging early.
- On confirmation, revoke sessions/tokens and rotate before further pivoting, because a
  live operator watching mailbox access may notice IR activity.

## References

- "Microsoft Entra ID OAuth Phishing and Detections" — Elastic Security Labs, 2025.
- "Hackers target Microsoft Entra accounts in device code vishing attacks" — BleepingComputer, 2025.
- "Device Code Phishing: OAuth Flow Abuse in Entra ID" — EtcSec; "Detecting device code phishing in Azure" — Silverfort.
- "OAuth Device Code Phishing Hits 340+ M365 Organizations" — Cloud Security Alliance Labs, Mar 2026.
- "Tycoon 2FA Operators Adopt OAuth Device Code Phishing" — eSentire, 2025.
- "Entra ID Attacks in Practice: Device Code Phishing, PRT Theft, and Conditional Access Bypass" — Hive Security.
- MITRE ATT&CK T1528 / T1550.001 / T1078.004 / T1098.
