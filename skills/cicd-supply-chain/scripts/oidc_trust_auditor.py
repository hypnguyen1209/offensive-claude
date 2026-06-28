#!/usr/bin/env python3
"""
oidc_trust_auditor.py - Audit cloud IAM trust policies tied to a CI OIDC provider for the
classic GitHub-Actions-OIDC misconfigurations:

  1. NO_SUB        -> trust validates only `aud` (no `sub` condition): ANY repo on github.com can assume.
  2. ORG_WILDCARD  -> wildcard bleeds into the org segment, e.g. sub like `repo:acme*` -> any org
                      starting "acme" can assume.
  3. STRINGEQ_WILD -> StringEquals used with a wildcard value (mis-scoped / never matches as intended).
  4. ORG_BROAD     -> `repo:org/*` allows every repo in the org (forks/dependabot/new repos).
  5. PR_TRUST      -> sub ends `:pull_request` -> any PR author (incl. external) runs under this trust.

Clouds:
  --cloud aws    : reads IAM roles via boto3 (needs configured creds; ReadOnly is enough).
  --cloud gcp    : parses a Workload Identity pool/provider config JSON (--file) for attribute mapping.
  --cloud azure  : parses federated-credential JSON (--file) for subject/issuer scoping.
  --file PATH    : audit a policy/config JSON offline (works for any cloud without live creds).

Usage:
  python3 oidc_trust_auditor.py --provider github --cloud aws --profile target
  python3 oidc_trust_auditor.py --provider github --cloud aws --file trust_policies.json
  python3 oidc_trust_auditor.py --provider github --cloud gcp --file wif_provider.json

Dependencies:  boto3 only for live --cloud aws (pip install boto3). Offline --file needs nothing extra.
"""
import argparse, json, re, sys

GH_ISSUER = "token.actions.githubusercontent.com"


def classify_aws_statement(stmt):
    """Return list of (severity, code, detail) findings for one trust-policy statement."""
    out = []
    principal = stmt.get("Principal", {})
    fed = principal.get("Federated", "")
    if isinstance(fed, list):
        fed = " ".join(fed)
    if GH_ISSUER not in str(fed):
        return out  # not a GitHub OIDC trust

    cond = stmt.get("Condition", {}) or {}
    # gather every sub/aud value across StringEquals / StringLike
    sub_vals, aud_present, op_for_sub = [], False, None
    for op in ("StringEquals", "StringLike", "ForAllValues:StringLike", "ForAnyValue:StringLike"):
        block = cond.get(op, {}) or {}
        for k, v in block.items():
            kl = k.lower()
            vals = v if isinstance(v, list) else [v]
            if kl.endswith(":sub"):
                sub_vals.extend(vals)
                op_for_sub = op
            if kl.endswith(":aud"):
                aud_present = True

    if not sub_vals:
        out.append(("CRITICAL", "NO_SUB",
                    "trust validates no `sub` condition (aud only) -> ANY github.com repo can assume"))
        return out

    for sv in sub_vals:
        # ORG_WILDCARD: wildcard before the first '/' (i.e. inside the org segment)
        org_seg = sv.split("/", 1)[0]
        if "*" in org_seg or "?" in org_seg:
            out.append(("CRITICAL", "ORG_WILDCARD",
                        f"sub `{sv}` wildcards the ORG segment -> foreign orgs matching it can assume"))
        if op_for_sub == "StringEquals" and ("*" in sv or "?" in sv):
            out.append(("HIGH", "STRINGEQ_WILD",
                        f"sub `{sv}` uses StringEquals with a wildcard (use StringLike or split)"))
        if re.search(r"^repo:[^/]+/\*(:\*)?$", sv):
            out.append(("HIGH", "ORG_BROAD",
                        f"sub `{sv}` allows every repo in the org (forks/dependabot/new repos)"))
        if sv.endswith(":pull_request") or ":pull_request" in sv:
            out.append(("HIGH", "PR_TRUST",
                        f"sub `{sv}` trusts pull_request refs -> any PR author can assume"))
    if not aud_present:
        out.append(("MEDIUM", "NO_AUD",
                    "no `aud` condition; also pin aud to sts.amazonaws.com"))
    return out


def audit_aws_live(profile):
    import boto3
    sess = boto3.Session(profile_name=profile) if profile else boto3.Session()
    iam = sess.client("iam")
    findings = []
    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        for role in page["Roles"]:
            doc = role.get("AssumeRolePolicyDocument", {})
            stmts = doc.get("Statement", [])
            if isinstance(stmts, dict):
                stmts = [stmts]
            for st in stmts:
                for sev, code, detail in classify_aws_statement(st):
                    findings.append({"severity": sev, "role": role["RoleName"],
                                     "arn": role["Arn"], "code": code, "detail": detail})
    return findings


def audit_file(path, cloud):
    data = json.load(open(path, encoding="utf-8"))
    findings = []
    if cloud == "aws":
        # accept a single policy, a list, or {RoleName: policyDoc}
        items = data if isinstance(data, list) else (
            list(data.items()) if isinstance(data, dict) and "Statement" not in data else [("(policy)", data)])
        for name, doc in (items if items and isinstance(items[0], tuple) else [(d.get("RoleName", "(role)"), d) for d in (data if isinstance(data, list) else [data])]):
            doc = doc.get("AssumeRolePolicyDocument", doc) if isinstance(doc, dict) else doc
            stmts = doc.get("Statement", []) if isinstance(doc, dict) else []
            if isinstance(stmts, dict):
                stmts = [stmts]
            for st in stmts:
                for sev, code, detail in classify_aws_statement(st):
                    findings.append({"severity": sev, "role": name, "code": code, "detail": detail})
    elif cloud == "gcp":
        cond = json.dumps(data)
        if GH_ISSUER not in cond and "githubusercontent" not in cond:
            print("note: GitHub issuer not found in GCP WIF config")
        if "attribute.repository" not in cond and "attributeCondition" not in cond:
            findings.append({"severity": "CRITICAL", "role": data.get("name", "(wif)"),
                             "code": "NO_ATTR_COND",
                             "detail": "no attributeCondition mapping repository/ref -> any repo can federate"})
        if re.search(r'assertion\.sub|attribute\.repository_owner["\s:]+[^"]*\*', cond):
            findings.append({"severity": "HIGH", "role": data.get("name", "(wif)"),
                             "code": "OWNER_WILD", "detail": "repository_owner wildcarded in WIF condition"})
    elif cloud == "azure":
        subj = data.get("subject", "")
        if not subj or subj.strip() == "*":
            findings.append({"severity": "CRITICAL", "role": data.get("name", "(fic)"),
                             "code": "NO_SUBJECT", "detail": "federated credential subject empty/wildcard"})
        if "pull_request" in subj:
            findings.append({"severity": "HIGH", "role": data.get("name", "(fic)"),
                             "code": "PR_TRUST", "detail": f"subject `{subj}` trusts pull_request"})
    return findings


def main():
    ap = argparse.ArgumentParser(description="Audit CI OIDC cloud trust policies")
    ap.add_argument("--provider", default="github", choices=["github"])
    ap.add_argument("--cloud", required=True, choices=["aws", "gcp", "azure"])
    ap.add_argument("--profile", help="AWS profile for live audit")
    ap.add_argument("--file", help="audit a policy/config JSON offline")
    ap.add_argument("--out")
    args = ap.parse_args()

    if args.file:
        findings = audit_file(args.file, args.cloud)
    elif args.cloud == "aws":
        findings = audit_aws_live(args.profile)
    else:
        sys.exit("live audit only implemented for --cloud aws; use --file for gcp/azure")

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: order.get(f["severity"], 9))
    for f in findings:
        print(f"[{f['severity']:8}] {f.get('role','?'):35} {f['code']:14} -- {f['detail']}")
    print(f"\n{len(findings)} OIDC trust finding(s).")
    if args.out:
        json.dump(findings, open(args.out, "w", encoding="utf-8"), indent=2)
        print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
