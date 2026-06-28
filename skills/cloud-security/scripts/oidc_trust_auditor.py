#!/usr/bin/env python3
"""
oidc_trust_auditor.py - Audit AWS IAM role trust policies for federation / cross-account
weaknesses, and extract secrets from Terraform state files.

FINDINGS
  - OIDC web-identity roles (GitHub Actions / Terraform Cloud / GitLab) with MISSING or
    WILDCARD `sub` conditions, or missing `aud` -> assumable by external workflows.
  - Cross-account roles trusting an external AWS account WITHOUT an sts:ExternalId condition
    -> confused-deputy risk.
  - Overly broad principals ("*", whole accounts) and conditionless trusts.
  - Terraform state (.tfstate) secret extraction (passwords, keys, tokens in cleartext).

USAGE
  # Audit all role trust policies using current AWS creds:
  python3 oidc_trust_auditor.py --profile compromised [--oidc]
  # Just pull secrets from a state file:
  python3 oidc_trust_auditor.py --tfstate ./terraform.tfstate
  # Audit a trust policy JSON file offline:
  python3 oidc_trust_auditor.py --policy-file trust.json

DEPENDENCIES
  pip install boto3   (only needed for the live AWS audit; --tfstate/--policy-file are offline)

OPSEC
  iam:ListRoles is read-only but logged. State-file reads from S3/Blob/GCS are object-access
  logged only if data-event logging is enabled. No mutating calls are made.
"""
import argparse
import json
import re
import sys

OIDC_PROVIDERS = ("token.actions.githubusercontent.com", "app.terraform.io",
                  "gitlab.com", "accounts.google.com", "oidc.eks")

SECRET_KEY_RE = re.compile(r"(pass|secret|token|priv.*key|api.?key|credential|access.?key)", re.I)


def as_list(x):
    return x if isinstance(x, list) else [x]


def audit_trust_policy(role_name, doc):
    """Return a list of finding strings for one AssumeRolePolicyDocument."""
    findings = []
    for stmt in as_list(doc.get("Statement", [])):
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal", {})
        conds = stmt.get("Condition", {})
        cond_flat = json.dumps(conds).lower()

        # --- OIDC web identity ---
        fed = principal.get("Federated") if isinstance(principal, dict) else None
        if fed and any(prov in json.dumps(fed) for prov in OIDC_PROVIDERS):
            has_sub = "sub" in cond_flat or ":sub" in cond_flat
            has_aud = "aud" in cond_flat
            if not has_sub:
                findings.append(f"[CRITICAL] {role_name}: OIDC trust ({fed}) has NO `sub` "
                                f"condition -> any workflow from the provider can assume it.")
            elif re.search(r'"[^"]*sub[^"]*"\s*:\s*"[^"]*\*', cond_flat) or "stringlike" in cond_flat:
                # wildcard sub via StringLike
                findings.append(f"[HIGH] {role_name}: OIDC trust uses wildcard/StringLike `sub` "
                                f"-> attacker may register a matching repo/org. Pin full sub.")
            if not has_aud:
                findings.append(f"[MEDIUM] {role_name}: OIDC trust missing `aud` condition "
                                f"-> token replay across audiences.")

        # --- Cross-account (AWS principal) ---
        aws_p = principal.get("AWS") if isinstance(principal, dict) else None
        if aws_p:
            principals = as_list(aws_p)
            if any(p == "*" for p in principals):
                findings.append(f"[CRITICAL] {role_name}: trust principal is '*' "
                                f"-> assumable by ANY AWS account.")
            for p in principals:
                # external account root/user without ExternalId condition
                if isinstance(p, str) and ":root" in p and "externalid" not in cond_flat:
                    findings.append(f"[HIGH] {role_name}: trusts external account {p} WITHOUT "
                                    f"sts:ExternalId -> confused-deputy risk.")
        # --- Conditionless service trust ---
        svc = principal.get("Service") if isinstance(principal, dict) else None
        if svc and not conds:
            findings.append(f"[LOW] {role_name}: service principal {svc} trust has NO conditions "
                            f"(consider aws:SourceArn/SourceAccount).")
    return findings


def live_audit(profile, oidc_only):
    try:
        import boto3
        from botocore.exceptions import ClientError, BotoCoreError
    except ImportError:
        sys.exit("[!] pip install boto3 for the live audit")
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    iam = session.client("iam")
    total = 0
    flagged = 0
    try:
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                total += 1
                doc = role.get("AssumeRolePolicyDocument", {})
                findings = audit_trust_policy(role["RoleName"], doc)
                if oidc_only:
                    findings = [f for f in findings if "OIDC" in f]
                if findings:
                    flagged += 1
                    for f in findings:
                        print(f"  {f}")
    except (ClientError, BotoCoreError) as e:
        sys.exit(f"[!] list_roles failed: {e}")
    print(f"\n[*] Audited {total} role(s); {flagged} with trust-policy findings.")


def extract_tfstate_secrets(path):
    try:
        with open(path) as fh:
            state = json.load(fh)
    except Exception as e:
        sys.exit(f"[!] could not read state: {e}")

    print(f"[*] Scanning {path} for cleartext secrets ...\n")
    hits = 0

    def walk(obj, trail):
        nonlocal hits
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (str, int)) and SECRET_KEY_RE.search(str(k)) and str(v):
                    print(f"  [SECRET] {'/'.join(trail + [str(k)])} = {str(v)[:80]}")
                    hits += 1
                else:
                    walk(v, trail + [str(k)])
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                walk(v, trail + [str(i)])

    # Outputs (often the highest value) then full resource attributes
    walk(state.get("outputs", {}), ["outputs"])
    for res in state.get("resources", []):
        rname = f"{res.get('type','?')}.{res.get('name','?')}"
        for inst in res.get("instances", []):
            walk(inst.get("attributes", {}), [rname])
    print(f"\n[*] {hits} candidate secret value(s) found.")


def main():
    p = argparse.ArgumentParser(description="AWS trust-policy + Terraform state auditor")
    p.add_argument("--profile", help="AWS profile for live role audit")
    p.add_argument("--oidc", action="store_true", help="only report OIDC findings")
    p.add_argument("--policy-file", help="audit a single trust-policy JSON offline")
    p.add_argument("--tfstate", help="extract secrets from a Terraform state file")
    a = p.parse_args()

    if a.tfstate:
        extract_tfstate_secrets(a.tfstate)
        return
    if a.policy_file:
        with open(a.policy_file) as fh:
            doc = json.load(fh)
        for f in audit_trust_policy(a.policy_file, doc):
            print(f"  {f}")
        return
    print("[*] Live AWS trust-policy audit\n")
    live_audit(a.profile, a.oidc)


if __name__ == "__main__":
    main()
