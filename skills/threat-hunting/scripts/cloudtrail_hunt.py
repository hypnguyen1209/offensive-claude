#!/usr/bin/env python3
"""
cloudtrail_hunt.py - Offline AWS CloudTrail threat-hunting analytics.

Runs behavior analytics over CloudTrail event JSON (a single file, a directory of the
gzipped/plain JSON CloudTrail digest files, or stdin) mapped to MITRE ATT&CK:
  - CloudTrail / FlowLog tampering (StopLogging/DeleteTrail/...)  (T1562.008) CRITICAL
  - Credential persistence: CreateAccessKey/LoginProfile on others (T1098)
  - IAM privilege escalation: Attach AdministratorAccess / PassRole (T1098 / T1078.004)
  - Recon burst: many Describe*/List* from one principal in a window (T1580 / T1526)
  - STS abuse: AssumeRole / GetSessionToken from unusual source       (T1550 / T1078.004)
  - Console login without MFA / root usage                            (T1078.004)

USAGE:
    python3 cloudtrail_hunt.py events.json [more.json|dir/ ...] [--window 600] [--json out.json]
    aws cloudtrail lookup-events --max-results 1000 | python3 cloudtrail_hunt.py -

DEPENDENCIES: Python 3.8+ stdlib only (handles .json and .json.gz).

This is a defensive cloud-hunting tool. Authorized use only.
"""
import argparse
import gzip
import json
import sys
from collections import defaultdict
from pathlib import Path

TAMPER = {"StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors",
          "DeleteFlowLogs", "DeleteLogGroup", "DeleteLogStream"}
CRED_PERSIST = {"CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile",
                "CreateUser", "CreateServiceSpecificCredential"}
PRIVESC = {"AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy",
           "PutUserPolicy", "PutRolePolicy", "AddUserToGroup", "PassRole",
           "CreatePolicyVersion", "SetDefaultPolicyVersion"}
ADMIN_HINTS = ("AdministratorAccess", "arn:aws:iam::aws:policy/AdministratorAccess", "*:*")
STS = {"AssumeRole", "GetSessionToken", "GetFederationToken", "AssumeRoleWithWebIdentity"}


def iter_records(path: Path):
    """Yield CloudTrail records from a .json / .json.gz file (handles {'Records':[...]} or list)."""
    opener = gzip.open if str(path).endswith(".gz") else open
    try:
        with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError) as e:
        print(f"[!] {path}: {e}", file=sys.stderr)
        return
    recs = data.get("Records") if isinstance(data, dict) else data
    if isinstance(recs, list):
        for r in recs:
            # `aws cloudtrail lookup-events` wraps the real event in CloudTrailEvent (a JSON string)
            if isinstance(r, dict) and "CloudTrailEvent" in r:
                try:
                    yield json.loads(r["CloudTrailEvent"])
                    continue
                except json.JSONDecodeError:
                    pass
            if isinstance(r, dict):
                yield r


def iter_stdin():
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        sys.exit(f"stdin is not valid JSON: {e}")
    recs = data.get("Events") or data.get("Records") or data
    if isinstance(recs, list):
        for r in recs:
            if isinstance(r, dict) and "CloudTrailEvent" in r:
                try:
                    yield json.loads(r["CloudTrailEvent"])
                    continue
                except json.JSONDecodeError:
                    pass
            if isinstance(r, dict):
                yield r


def arn_of(rec):
    ui = rec.get("userIdentity", {}) or {}
    return ui.get("arn") or ui.get("principalId") or ui.get("type", "unknown")


def analyze(rec, recon_state, findings):
    name = rec.get("eventName", "")
    src = rec.get("sourceIPAddress", "")
    t = rec.get("eventTime", "")
    arn = arn_of(rec)
    ui = rec.get("userIdentity", {}) or {}

    def add(sev, attck, title, detail):
        findings.append({"severity": sev, "attck": attck, "title": title,
                         "time": t, "principal": arn, "src": src, "detail": detail})

    if name in TAMPER:
        add("critical", "T1562.008", "CloudTrail / FlowLog tampering", f"{name}")

    if name in CRED_PERSIST:
        req = rec.get("requestParameters", {}) or {}
        target = req.get("userName", "")
        caller = ui.get("userName", "")
        if name == "CreateAccessKey" and target and caller and target != caller:
            add("high", "T1098", "Access key created for ANOTHER user",
                f"{caller} created key for {target}")
        else:
            add("medium", "T1098", "Credential/identity creation", f"{name} target={target or '?'}")

    if name in PRIVESC:
        req = rec.get("requestParameters", {}) or {}
        blob = json.dumps(req).lower()
        if any(h.lower() in blob for h in ADMIN_HINTS):
            add("high", "T1098/T1078.004", "IAM privilege escalation (admin policy)",
                f"{name} :: {json.dumps(req)[:200]}")
        else:
            add("medium", "T1098", "IAM policy/role modification", f"{name}")

    if name in STS:
        add("low", "T1550/T1078.004", "STS token issuance", f"{name} from {src}")

    if name == "ConsoleLogin":
        resp = rec.get("responseElements", {}) or {}
        ai = rec.get("additionalEventData", {}) or {}
        if ai.get("MFAUsed") == "No" and resp.get("ConsoleLogin") == "Success":
            sev = "high" if ui.get("type") == "Root" else "medium"
            add(sev, "T1078.004", "Console login WITHOUT MFA",
                f"type={ui.get('type','?')} mfa=No")

    # Recon-burst accumulation (Describe*/List*/Get*)
    if name.startswith(("Describe", "List", "Get")) and name not in STS:
        recon_state[(arn, src)].append((t, name))


def main():
    ap = argparse.ArgumentParser(description="Offline AWS CloudTrail threat-hunting analytics")
    ap.add_argument("paths", nargs="*", help="CloudTrail .json/.json.gz files or dirs ('-' = stdin)")
    ap.add_argument("--recon-threshold", type=int, default=40,
                    help="distinct Describe/List/Get calls per principal to flag recon")
    ap.add_argument("--json", help="write findings to JSON file")
    args = ap.parse_args()

    targets = []
    use_stdin = False
    for p in args.paths:
        if p == "-":
            use_stdin = True
            continue
        pp = Path(p)
        if pp.is_dir():
            targets += sorted(list(pp.rglob("*.json")) + list(pp.rglob("*.json.gz")))
        elif pp.exists():
            targets.append(pp)
    if not targets and not use_stdin:
        ap.error("provide CloudTrail files/dirs or '-' for stdin")

    findings = []
    recon_state = defaultdict(list)

    if use_stdin:
        for rec in iter_stdin():
            analyze(rec, recon_state, findings)
    for f in targets:
        print(f"[*] Parsing {f}", file=sys.stderr)
        for rec in iter_records(f):
            analyze(rec, recon_state, findings)

    # Evaluate recon bursts
    for (arn, src), calls in recon_state.items():
        distinct = {c[1] for c in calls}
        if len(distinct) >= args.recon_threshold:
            findings.append({
                "severity": "medium", "attck": "T1580/T1526",
                "title": "Cloud enumeration burst",
                "time": calls[0][0], "principal": arn, "src": src,
                "detail": f"{len(distinct)} distinct Describe/List/Get calls ({len(calls)} total)"})

    sev_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    findings.sort(key=lambda x: sev_rank[x["severity"]], reverse=True)

    for x in findings:
        print(f"[{x['severity'].upper():8}] {x['attck']:18} {x['title']}")
        print(f"           {x['time']}  {x['principal']}  src={x['src']}")
        print(f"           {x['detail']}")

    print(f"\n[=] {len(findings)} finding(s)", file=sys.stderr)
    if args.json:
        Path(args.json).write_text(json.dumps(findings, indent=2), encoding="utf-8")
        print(f"[+] Wrote {args.json}", file=sys.stderr)


if __name__ == "__main__":
    main()
