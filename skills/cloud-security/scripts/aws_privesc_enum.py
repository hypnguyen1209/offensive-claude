#!/usr/bin/env python3
"""
aws_privesc_enum.py - Enumerate an AWS principal's effective permissions and score
known IAM privilege-escalation paths (Rhino Security Labs primitive set + sts:AssumeRoot).

USAGE
  python3 aws_privesc_enum.py --profile compromised [--json paths.json] [--region us-east-1]
  python3 aws_privesc_enum.py --access-key AKIA... --secret-key ... [--session-token ...]

WHAT IT DOES
  1. sts get-caller-identity -> who am I.
  2. Pulls effective permissions via iam:SimulatePrincipalPolicy for every action that
     participates in a known privesc path (no policy writes are performed).
  3. Reports each privesc PATH whose required actions are all Allowed.
  4. Optionally checks Organizations management/delegated-admin context for sts:AssumeRoot.

DEPENDENCIES
  pip install boto3
  Read-only: only sts:GetCallerIdentity + iam:SimulatePrincipalPolicy are called.

OPSEC
  SimulatePrincipalPolicy and GetCallerIdentity are logged in CloudTrail; the
  enum-then-write pattern is a common detection. This tool only enumerates.
"""
import argparse
import json
import sys

try:
    import boto3
    from botocore.exceptions import ClientError, BotoCoreError
except ImportError:
    sys.exit("[!] pip install boto3")

# path_name -> list of actions that ALL must be allowed for the path to work
PRIVESC_PATHS = {
    "CreatePolicyVersion (rewrite attached policy -> admin)": ["iam:CreatePolicyVersion"],
    "SetDefaultPolicyVersion (activate permissive old version)": ["iam:SetDefaultPolicyVersion"],
    "AttachUserPolicy (attach AdministratorAccess)": ["iam:AttachUserPolicy"],
    "AttachRolePolicy (attach admin to assumable role)": ["iam:AttachRolePolicy"],
    "AttachGroupPolicy (attach admin to your group)": ["iam:AttachGroupPolicy"],
    "PutUserPolicy (inline admin on self)": ["iam:PutUserPolicy"],
    "PutRolePolicy (inline admin on role)": ["iam:PutRolePolicy"],
    "CreateLoginProfile (set console pw for any user)": ["iam:CreateLoginProfile"],
    "UpdateLoginProfile (reset console pw of any user)": ["iam:UpdateLoginProfile"],
    "CreateAccessKey (mint keys for another user)": ["iam:CreateAccessKey"],
    "AddUserToGroup (join admin group)": ["iam:AddUserToGroup"],
    "PassRole + Lambda (run code as admin role)": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
    "PassRole + EC2 RunInstances (admin instance profile)": ["iam:PassRole", "ec2:RunInstances"],
    "PassRole + Glue DevEndpoint": ["iam:PassRole", "glue:CreateDevEndpoint"],
    "PassRole + CloudFormation CreateStack": ["iam:PassRole", "cloudformation:CreateStack"],
    "UpdateFunctionCode (backdoor existing privileged Lambda)": ["lambda:UpdateFunctionCode"],
    "sts:AssumeRole (broad trust -> privileged role)": ["sts:AssumeRole"],
    "CreateRole + AttachRolePolicy + PassRole": ["iam:CreateRole", "iam:AttachRolePolicy", "iam:PassRole"],
    "UpdateAssumeRolePolicy (rewrite role trust -> assume it)": ["iam:UpdateAssumeRolePolicy", "sts:AssumeRole"],
}


def all_actions():
    seen = set()
    for acts in PRIVESC_PATHS.values():
        seen.update(acts)
    return sorted(seen)


def session_from_args(a):
    kw = {}
    if a.profile:
        kw["profile_name"] = a.profile
    s = boto3.Session(**kw)
    if a.access_key:
        s = boto3.Session(
            aws_access_key_id=a.access_key,
            aws_secret_access_key=a.secret_key,
            aws_session_token=a.session_token,
        )
    return s


def simulate(iam, arn, actions):
    """Returns dict action -> 'allowed'|'denied'. Batched by 100 (API limit)."""
    result = {}
    for i in range(0, len(actions), 50):
        batch = actions[i:i + 50]
        try:
            resp = iam.simulate_principal_policy(PolicySourceArn=arn, ActionNames=batch)
        except ClientError as e:
            for act in batch:
                result[act] = f"error:{e.response['Error']['Code']}"
            continue
        for ev in resp.get("EvaluationResults", []):
            result[ev["EvalActionName"]] = (
                "allowed" if ev["EvalDecision"] == "allowed" else "denied"
            )
    return result


def check_assume_root(session):
    """Best-effort: are we in an Org mgmt/delegated-admin context (AssumeRoot prereq)?"""
    try:
        org = session.client("organizations")
        desc = org.describe_organization()
        accounts = org.list_accounts().get("Accounts", [])
        mgmt = desc["Organization"].get("MasterAccountId")
        return {
            "in_organization": True,
            "management_account": mgmt,
            "member_accounts": [a["Id"] for a in accounts if a["Id"] != mgmt],
            "note": "If callable, sts:AssumeRoot can yield root creds for these member accounts "
                    "(regional STS endpoint only).",
        }
    except (ClientError, BotoCoreError):
        return {"in_organization": False}


def main():
    p = argparse.ArgumentParser(description="AWS IAM privesc path enumerator")
    p.add_argument("--profile")
    p.add_argument("--access-key")
    p.add_argument("--secret-key")
    p.add_argument("--session-token")
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--json", help="write full results to JSON")
    a = p.parse_args()

    session = session_from_args(a)
    sts = session.client("sts", region_name=a.region)
    try:
        ident = sts.get_caller_identity()
    except (ClientError, BotoCoreError) as e:
        sys.exit(f"[!] get-caller-identity failed: {e}")

    arn = ident["Arn"]
    print(f"[*] Caller : {arn}")
    print(f"[*] Account: {ident['Account']}\n")

    iam = session.client("iam", region_name=a.region)
    decisions = simulate(iam, arn, all_actions())

    found = []
    for path, needed in PRIVESC_PATHS.items():
        if all(decisions.get(act) == "allowed" for act in needed):
            found.append({"path": path, "actions": needed})

    if found:
        print(f"[+] {len(found)} viable privilege-escalation path(s):\n")
        for f in found:
            print(f"  [PRIVESC] {f['path']}")
            print(f"            requires: {', '.join(f['actions'])}")
    else:
        print("[-] No direct privesc path from the known primitive set.")

    org = check_assume_root(session)
    if org.get("in_organization"):
        print(f"\n[+] Organizations context: mgmt={org['management_account']} "
              f"members={len(org['member_accounts'])}")
        print("    -> evaluate sts:AssumeRoot toward member accounts (see aws-iam-privesc.md)")

    out = {"caller": ident, "decisions": decisions, "privesc_paths": found, "organizations": org}
    if a.json:
        with open(a.json, "w") as fh:
            json.dump(out, fh, indent=2, default=str)
        print(f"\n[*] Full results -> {a.json}")


if __name__ == "__main__":
    main()
