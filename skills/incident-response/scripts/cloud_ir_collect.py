#!/usr/bin/env python3
"""
cloud_ir_collect.py - Cloud incident-response evidence collection + identity-plane containment.

Wraps awscli / az / gcloud to (a) collect control-plane evidence to immutable-friendly output and
(b) perform identity-FIRST containment (revoke keys/tokens) in parallel with network controls.
Aligns with NIST SP 800-61r3 (cloud-scoped) and SP 800-201 forensic readiness.

Usage:
  # AWS: collect CloudTrail for an actor + GuardDuty IMDSv2/SSRF exfil findings; contain a key.
  python3 cloud_ir_collect.py aws --actor compromised_user \
      --collect-cloudtrail --collect-guardduty \
      --contain-key AKIA... --contain-user compromised_user \
      --enforce-imdsv2 i-0123456789abcdef0 --snapshot-volume vol-0abc... \
      [--dry-run]
  # Azure/Entra: pull risky sign-ins KQL + disable user + REVOKE tokens (kills stolen sessions).
  python3 cloud_ir_collect.py azure --actor victim@corp.com --revoke-sessions --disable-user
  # GCP: pull admin-activity audit logs for a principal.
  python3 cloud_ir_collect.py gcp --actor attacker@corp.com --project my-proj --collect-audit

Dependencies: Python 3.8+, and the relevant provider CLI authenticated as a DEDICATED IR principal
  (so your actions are attributable and separate from the attacker). Containment actions require
  --confirm unless --dry-run; --dry-run only prints commands.
Notes: PRESERVE before REMEDIATE - snapshot + export logs to a destination the attacker cannot reach
  before destructive containment. Containment calls are logged in the same trail you analyse.
"""
import argparse
import datetime
import json
import os
import subprocess
import sys


def ts():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def run(cmd, dry, outfile=None):
    print("[CMD] " + " ".join(cmd), file=sys.stderr)
    if dry:
        return ""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    except FileNotFoundError:
        print(f"[!] CLI not found: {cmd[0]}", file=sys.stderr)
        return ""
    if p.returncode != 0:
        print(f"[!] rc={p.returncode}: {p.stderr.strip()[:400]}", file=sys.stderr)
    if outfile and p.stdout:
        with open(outfile, "w", encoding="utf-8") as fh:
            fh.write(p.stdout)
        print(f"[+] wrote {outfile}")
    return p.stdout


# --------------------------------------------------------------------------- AWS
def aws(args, outdir):
    if args.collect_cloudtrail and args.actor:
        run(["aws", "cloudtrail", "lookup-events",
             "--lookup-attributes", f"AttributeKey=Username,AttributeValue={args.actor}",
             "--max-results", "200", "--output", "json"],
            args.dry_run, os.path.join(outdir, "cloudtrail_actor.json"))
    if args.collect_cloudtrail:
        # detect logging tamper (attacker's first move)
        run(["aws", "cloudtrail", "lookup-events",
             "--lookup-attributes", "AttributeKey=EventName,AttributeValue=StopLogging",
             "--output", "json"],
            args.dry_run, os.path.join(outdir, "cloudtrail_stoplogging.json"))
    if args.collect_guardduty:
        det = run(["aws", "guardduty", "list-detectors", "--query", "DetectorIds[0]",
                   "--output", "text"], args.dry_run).strip() or "DETECTOR_ID"
        crit = ('{"Criterion":{"type":{"Eq":['
                '"UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"]}}}')
        run(["aws", "guardduty", "list-findings", "--detector-id", det,
             "--finding-criteria", crit, "--output", "json"],
            args.dry_run, os.path.join(outdir, "guardduty_imds_exfil.json"))
    # PRESERVE before remediate
    if args.snapshot_volume:
        run(["aws", "ec2", "create-snapshot", "--volume-id", args.snapshot_volume,
             "--description", f"IR-evidence-{ts()}", "--output", "json"],
            args.dry_run, os.path.join(outdir, "snapshot.json"))
    # CONTAIN (identity first)
    if args.contain_key and (args.dry_run or args.confirm):
        run(["aws", "iam", "update-access-key", "--access-key-id", args.contain_key,
             "--status", "Inactive", "--user-name", args.contain_user or args.actor or "UNKNOWN"],
            args.dry_run)
    if args.contain_user and (args.dry_run or args.confirm):
        deny = ('{"Version":"2012-10-17","Statement":[{"Effect":"Deny",'
                '"Action":"*","Resource":"*"}]}')
        run(["aws", "iam", "put-user-policy", "--user-name", args.contain_user,
             "--policy-name", "IR-DenyAll", "--policy-document", deny], args.dry_run)
    if args.enforce_imdsv2 and (args.dry_run or args.confirm):
        run(["aws", "ec2", "modify-instance-metadata-options",
             "--instance-id", args.enforce_imdsv2,
             "--http-tokens", "required", "--http-endpoint", "enabled"], args.dry_run)


# --------------------------------------------------------------------------- Azure / Entra
def azure(args, outdir):
    actor = args.actor or "victim@corp.com"
    kql = (f'SigninLogs | where TimeGenerated > ago(14d) '
           f'| where UserPrincipalName == "{actor}" '
           f'| summarize signins=count(), ips=make_set(IPAddress), apps=make_set(AppDisplayName) '
           f'by bin(TimeGenerated,1h), Location, ResultType, '
           f'tostring(RiskLevelDuringSignIn)')
    with open(os.path.join(outdir, "risky_signins.kql"), "w", encoding="utf-8") as fh:
        fh.write(kql + "\n")
    print("[+] wrote risky_signins.kql (run in Sentinel / Log Analytics)")
    # CONTAIN: disable + revoke sessions (token theft mitigation)
    if args.disable_user and (args.dry_run or args.confirm):
        run(["az", "ad", "user", "update", "--id", actor, "--account-enabled", "false"],
            args.dry_run)
    if args.revoke_sessions and (args.dry_run or args.confirm):
        uri = f"https://graph.microsoft.com/v1.0/users/{actor}/revokeSignInSessions"
        run(["az", "rest", "--method", "POST", "--uri", uri], args.dry_run)


# --------------------------------------------------------------------------- GCP
def gcp(args, outdir):
    if args.collect_audit and args.actor:
        flt = (f'protoPayload.authenticationInfo.principalEmail="{args.actor}" '
               f'AND timestamp>="{(datetime.date.today()-datetime.timedelta(days=14)).isoformat()}T00:00:00Z"')
        cmd = ["gcloud", "logging", "read", flt, "--format", "json", "--limit", "500"]
        if args.project:
            cmd += ["--project", args.project]
        run(cmd, args.dry_run, os.path.join(outdir, "gcp_audit.json"))


def main() -> int:
    ap = argparse.ArgumentParser(description="Cloud IR collection + identity-plane containment")
    ap.add_argument("provider", choices=["aws", "azure", "gcp"])
    ap.add_argument("--actor", help="compromised principal/user")
    ap.add_argument("--out", default=f"./cloud_ir_{ts()}")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--confirm", action="store_true",
                    help="actually perform containment (otherwise containment is skipped)")
    # AWS
    ap.add_argument("--collect-cloudtrail", action="store_true")
    ap.add_argument("--collect-guardduty", action="store_true")
    ap.add_argument("--snapshot-volume")
    ap.add_argument("--contain-key"); ap.add_argument("--contain-user")
    ap.add_argument("--enforce-imdsv2", metavar="INSTANCE_ID")
    # Azure
    ap.add_argument("--disable-user", action="store_true")
    ap.add_argument("--revoke-sessions", action="store_true")
    # GCP
    ap.add_argument("--collect-audit", action="store_true")
    ap.add_argument("--project")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    print(f"[*] provider={args.provider} out={os.path.abspath(args.out)} "
          f"dry_run={args.dry_run} confirm={args.confirm}")
    print("[*] DOCTRINE: preserve (snapshot+immutable log export) BEFORE remediate; "
          "revoke tokens (not just disable user).")
    if not args.dry_run and not args.confirm:
        print("[i] containment actions are SKIPPED without --confirm (collection still runs).")

    {"aws": aws, "azure": azure, "gcp": gcp}[args.provider](args, args.out)

    manifest = {"provider": args.provider, "generated": ts(), "actor": args.actor,
                "outputs": os.listdir(args.out)}
    with open(os.path.join(args.out, "_manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
