# Cloud Incident Response — AWS, Azure (Entra), GCP

ATT&CK: T1552.005 (Cloud Instance Metadata API), T1078.004 (Cloud Accounts), T1528 (Steal
Application Access Token), T1098.001 (Additional Cloud Credentials), T1562.008 (Disable Cloud Logs),
T1530 (Data from Cloud Storage). CWE-918 (SSRF), CWE-287 (Improper Authentication).

## Theory / Mechanism

Cloud IR is **not** host-centric — the **management API / control plane** is the crime scene and the
attack surface. You reconstruct the timeline from **CloudTrail / Azure Activity+Entra / GCP Audit
Logs**, not endpoint telemetry, and lateral movement is an **identity-graph traversal** problem
(role-assumption chains, federated SSO, OAuth tokens), not a network problem.

Three doctrines:
1. **Forensic readiness must pre-exist.** Snapshot policies, memory-capture automation, and
   tamper-resistant log forwarding must run as *standing infrastructure*. Without them, the evidence
   window is already closed when you arrive (ephemeral instances/containers vanish).
2. **Preserve before remediate.** Snapshot volumes and export logs to **immutable** storage *before*
   touching the resource — remediation often destroys ephemeral evidence.
3. **Identity-plane containment runs in parallel with network controls.** Revoke keys, restrict IAM,
   expire tokens, and audit federation trust at the same time as you isolate networks — network
   isolation alone does not stop an identity-driven attacker.

Signature attack: **IMDSv2/SSRF credential theft (AWS).** An SSRF in an app reaches
`http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` and steals the instance
role's temporary creds, then uses them from an external IP. **IMDSv2** requires a session token
(PUT then GET with `X-aws-ec2-metadata-token`), defeating most SSRF — but IMDSv1 fallback is often
left enabled for legacy apps. GuardDuty fires
`UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` when role creds are used from
a non-AWS IP.

## Modern 2024-2026 currency (verified)

- **NIST SP 800-61r3 (Apr 2025)** retires the standalone 4-phase IR lifecycle and integrates IR into
  the **six CSF 2.0 functions**, explicitly scoping cloud. **NIST SP 800-201 (Jul 2024)** — Cloud
  Computing Forensic Reference Architecture — codifies cloud forensic readiness.
- **AWS** — CloudTrail (all regions, management **and data** events, versioned + Object-Lock S3),
  GuardDuty (CloudTrail + VPC Flow + DNS), enforce **IMDSv2-only** via SCP. Attackers disable logging
  first (`StopLogging`, `DeleteTrail`) — alert on it.
- **Azure / Entra ID** — managed identities & service principals **accumulate** permissions; compromise
  a function app and you inherit its (often over-scoped) identity. Investigate via Entra **sign-in**,
  **audit**, and storage logs in **Sentinel** with KQL; enable **Identity Protection** for risky
  sign-ins. Token theft (T1528) — stolen refresh/PRT/OAuth tokens bypass MFA — is the dominant 2024-26
  Entra vector.
- **GCP** — Cloud Audit Logs (Admin Activity / Data Access / System Event), VPC Flow Logs, Security
  Command Center; navigate the org→folder→project hierarchy and IAM bindings.
- **Real incident anchor:** **LinkPro** eBPF rootkit (Synacktiv, Oct 2025) entered an **AWS/EKS**
  estate via Jenkins **CVE-2024-23897**, deployed through a malicious Docker image (`kvlnt/vv`) with
  full-FS root → container escape + pod-credential harvesting. Cloud IR must include container/EKS
  forensics and out-of-band memory capture (see memory-forensics ref).

## Complete working commands

### AWS — collect, then contain (identity-plane first)
```bash
# Timeline from CloudTrail (who/what/when). Look-up by actor:
aws cloudtrail lookup-events --lookup-attributes \
  AttributeKey=Username,AttributeValue=compromised_user \
  --start-time 2026-06-01 --end-time 2026-06-28 --max-results 200
# Detect logging tamper (attacker's first move):
aws cloudtrail lookup-events --lookup-attributes \
  AttributeKey=EventName,AttributeValue=StopLogging
# GuardDuty findings (incl. the IMDSv2/SSRF exfil signature):
DID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty list-findings --detector-id "$DID" \
  --finding-criteria '{"Criterion":{"type":{"Eq":["UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"]}}}'
# EC2 evidence: snapshot the volume BEFORE touching the instance:
aws ec2 create-snapshot --volume-id vol-XXX --description "IR-evidence-$(date -u +%FT%TZ)"
# CONTAIN identity: deactivate key + attach explicit DenyAll (parallel to network):
aws iam update-access-key --access-key-id AKIA... --status Inactive --user-name compromised_user
aws iam put-user-policy --user-name compromised_user --policy-name IR-DenyAll \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
# CONTAIN network at subnet level (faster/broader than SG) + enforce IMDSv2:
aws ec2 modify-instance-metadata-options --instance-id i-XXX \
  --http-tokens required --http-endpoint enabled
```

### Azure / Entra ID — token theft & containment
```bash
# Risky sign-ins / impossible travel for the victim (Sentinel KQL):
cat <<'KQL'
SigninLogs
| where TimeGenerated > ago(14d)
| where UserPrincipalName == "victim@corp.com"
| extend risk = tostring(RiskLevelDuringSignIn)
| summarize signins=count(), ips=make_set(IPAddress), apps=make_set(AppDisplayName)
    by bin(TimeGenerated,1h), Location, ResultType, risk
KQL
# Service-principal / OAuth grant abuse (consent-phishing persistence):
cat <<'KQL'
AuditLogs
| where OperationName has_any ("Add service principal credentials","Consent to application",
        "Add OAuth2PermissionGrant")
| project TimeGenerated, InitiatedBy, TargetResources, OperationName
KQL
# CONTAIN: disable account + REVOKE all refresh tokens/sessions (kills stolen tokens):
az ad user update --id victim@corp.com --account-enabled false
az rest --method POST --uri "https://graph.microsoft.com/v1.0/users/victim@corp.com/revokeSignInSessions"
```

### GCP — audit-log timeline
```bash
gcloud logging read \
  'protoPayload.authenticationInfo.principalEmail="attacker@corp.com"
   AND timestamp>="2026-06-01T00:00:00Z"' \
  --project PROJECT --format json --limit 500 > gcp_admin_activity.json
gcloud scc findings list ORG_ID --filter='state="ACTIVE"' --format json
```

The orchestrating script `scripts/cloud_ir_collect.py` automates collection + the containment calls
above per provider with `--dry-run` safety.

## Detection

```yaml
title: AWS CloudTrail logging disabled (anti-forensics, cloud)
id: aws-stoplogging-ir
status: stable
logsource: { product: aws, service: cloudtrail }
detection:
  sel:
    eventSource: 'cloudtrail.amazonaws.com'
    eventName: ['StopLogging','DeleteTrail','UpdateTrail','PutEventSelectors']
  condition: sel
level: high
falsepositives: [planned trail reconfiguration in a change window]
```

Cloud IOCs: instance-role creds used from a non-AWS ASN; `CreateAccessKey`/`AttachUserPolicy` by an
unusual principal; new SP credentials / OAuth grants; `StopLogging`/`DeleteTrail`; cross-account
`AssumeRole` chains to never-seen accounts; mass `GetObject`/`ListBucket` (exfil).

## OPSEC

- **Touches:** snapshots, log exports, IAM changes — all logged in the same trail you're analysing.
  Run from a **dedicated IR principal** with its own role so your actions are attributable and don't
  blend with the attacker's.
- **Cleanup:** detach temporary DenyAll/quarantine policies after eradication; delete IR snapshots per
  retention; remove the IR principal's elevated grants.
- **Evasion awareness:** stream logs to a SIEM/account the attacker **cannot reach** from the
  compromised tenant; assume they may delete/alter logs in-account. Revoke tokens (not just disable
  the user) — a disabled user with a live refresh token is still active until revocation.

## References

- NIST SP 800-61r3 (Apr 2025) ; NIST SP 800-201 (Jul 2024)
- Sygnia "IR to Cloud Security Incidents: AWS, Azure, GCP best practices"
- "Cloud Incident Response: Why Cloud Breaches Require a Different Playbook" (daylight.ai)
- AWS GuardDuty finding types — InstanceCredentialExfiltration.OutsideAWS
- Synacktiv LinkPro (AWS/EKS, Jenkins CVE-2024-23897)
