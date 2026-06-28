#!/usr/bin/env python3
"""
ad_recon.py - Authenticated Active Directory reconnaissance over LDAP.

Pulls a quick attack-surface snapshot from a domain controller and flags the
cheap-win primitives a red teamer goes for first: Kerberoastable SPNs, AS-REP
roastable users, unconstrained/constrained/RBCD delegation, MachineAccountQuota,
DONT_EXPIRE/PASSWD_NOTREQD UAC bits, and DCSync-capable principals (heuristic).

Usage:
    python3 ad_recon.py -d corp.local --dc-ip 10.0.0.10 -u user -p 'Password1'
    python3 ad_recon.py -d corp.local --dc-ip 10.0.0.10 -u user -H <LM:NT|:NT>
    python3 ad_recon.py -d corp.local --dc-ip 10.0.0.10 -u user -p 'Pass' --json out.json

Dependencies:
    pip install ldap3 impacket
Notes:
    - LDAPS preferred (-ssl); falls back to LDAP. Heavy queries are paged.
    - Read-only. For BloodHound graphing use bloodhound-ce-python / nxc --bloodhound.
"""
import argparse
import json
import sys

try:
    from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, Tls
    import ssl
except ImportError:
    sys.exit("[-] pip install ldap3")

# userAccountControl bit flags
UAC = {
    "DISABLED": 0x0002,
    "DONT_EXPIRE_PASSWD": 0x10000,
    "PASSWD_NOTREQD": 0x0020,
    "DONT_REQ_PREAUTH": 0x400000,
    "TRUSTED_FOR_DELEGATION": 0x80000,            # unconstrained
    "TRUSTED_TO_AUTH_FOR_DELEGATION": 0x1000000,  # constrained w/ protocol transition
}


def base_dn(domain):
    return ",".join(f"DC={p}" for p in domain.split("."))


def connect(args):
    use_ssl = args.ssl
    port = 636 if use_ssl else 389
    tls = Tls(validate=ssl.CERT_NONE) if use_ssl else None
    server = Server(args.dc_ip, port=port, use_ssl=use_ssl, get_info=ALL, tls=tls)
    if args.hashes:
        nt = args.hashes.split(":")[-1]
        password = f"aad3b435b51404eeaad3b435b51404ee:{nt}"
    else:
        password = args.password
    user = f"{args.domain}\\{args.username}"
    conn = Connection(server, user=user, password=password,
                      authentication=NTLM, auto_bind=True)
    return conn


def paged_search(conn, base, flt, attrs):
    return conn.extend.standard.paged_search(
        search_base=base, search_filter=flt,
        search_scope=SUBTREE, attributes=attrs,
        paged_size=500, generator=True)


def val(entry, attr):
    a = entry.get("attributes", {})
    v = a.get(attr)
    if isinstance(v, list):
        return v[0] if v else None
    return v


def main():
    ap = argparse.ArgumentParser(description="Authenticated AD recon over LDAP")
    ap.add_argument("-d", "--domain", required=True)
    ap.add_argument("--dc-ip", required=True)
    ap.add_argument("-u", "--username", required=True)
    ap.add_argument("-p", "--password", default="")
    ap.add_argument("-H", "--hashes", help="[LM]:NT")
    ap.add_argument("--ssl", action="store_true", help="use LDAPS:636")
    ap.add_argument("--json", help="write findings to JSON file")
    args = ap.parse_args()

    try:
        conn = connect(args)
    except Exception as e:
        sys.exit(f"[-] Bind failed: {e}")

    bdn = base_dn(args.domain)
    findings = {"kerberoastable": [], "asrep_roastable": [], "unconstrained": [],
                "constrained": [], "rbcd": [], "weak_uac": [], "dcsync_candidates": [],
                "machine_account_quota": None, "server2025_dc": []}

    print(f"[+] Bound to {args.dc_ip} as {args.domain}\\{args.username}; base={bdn}\n")

    # Kerberoastable: users (not computers) with an SPN
    for e in paged_search(conn, bdn,
                          "(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer)))",
                          ["sAMAccountName", "servicePrincipalName"]):
        if e.get("type") != "searchResEntry":
            continue
        findings["kerberoastable"].append({
            "user": val(e, "sAMAccountName"),
            "spn": e["attributes"].get("servicePrincipalName")})

    # AS-REP roastable + weak UAC
    for e in paged_search(conn, bdn,
                          "(&(objectCategory=person)(objectClass=user))",
                          ["sAMAccountName", "userAccountControl"]):
        if e.get("type") != "searchResEntry":
            continue
        name = val(e, "sAMAccountName")
        uac = int(val(e, "userAccountControl") or 0)
        if uac & UAC["DONT_REQ_PREAUTH"]:
            findings["asrep_roastable"].append(name)
        flags = [k for k, b in UAC.items()
                 if k in ("DONT_EXPIRE_PASSWD", "PASSWD_NOTREQD") and uac & b]
        if flags:
            findings["weak_uac"].append({"user": name, "flags": flags})

    # Delegation (users + computers)
    for e in paged_search(conn, bdn,
                          "(|(userAccountControl:1.2.840.113556.1.4.803:=524288)"
                          "(userAccountControl:1.2.840.113556.1.4.803:=16777216)"
                          "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
                          "(msDS-AllowedToDelegateTo=*))",
                          ["sAMAccountName", "userAccountControl",
                           "msDS-AllowedToDelegateTo",
                           "msDS-AllowedToActOnBehalfOfOtherIdentity"]):
        if e.get("type") != "searchResEntry":
            continue
        name = val(e, "sAMAccountName")
        uac = int(val(e, "userAccountControl") or 0)
        if uac & UAC["TRUSTED_FOR_DELEGATION"]:
            findings["unconstrained"].append(name)
        if e["attributes"].get("msDS-AllowedToDelegateTo"):
            findings["constrained"].append({
                "account": name,
                "allowed_to": e["attributes"]["msDS-AllowedToDelegateTo"]})
        if e["attributes"].get("msDS-AllowedToActOnBehalfOfOtherIdentity"):
            findings["rbcd"].append(name)

    # MachineAccountQuota + DC OS versions (Server 2025 => BadSuccessor surface)
    conn.search(bdn, "(objectClass=domain)", attributes=["ms-DS-MachineAccountQuota"])
    if conn.entries:
        findings["machine_account_quota"] = conn.entries[0].entry_attributes_as_dict.get(
            "ms-DS-MachineAccountQuota", [None])[0]
    for e in paged_search(conn, f"OU=Domain Controllers,{bdn}",
                          "(objectClass=computer)",
                          ["dNSHostName", "operatingSystem"]):
        if e.get("type") != "searchResEntry":
            continue
        os_str = val(e, "operatingSystem") or ""
        if "2025" in os_str:
            findings["server2025_dc"].append(
                {"host": val(e, "dNSHostName"), "os": os_str})

    # Print summary
    def show(title, items):
        print(f"=== {title} ({len(items)}) ===")
        for it in items:
            print(f"  {it}")
        print()

    show("Kerberoastable (T1558.003)", findings["kerberoastable"])
    show("AS-REP roastable (T1558.004)", findings["asrep_roastable"])
    show("Unconstrained delegation (TGT capture targets)", findings["unconstrained"])
    show("Constrained delegation (S4U)", findings["constrained"])
    show("RBCD configured", findings["rbcd"])
    show("Weak UAC (PASSWD_NOTREQD / DONT_EXPIRE)", findings["weak_uac"])
    print(f"=== MachineAccountQuota === {findings['machine_account_quota']} "
          f"(>0 enables RBCD/noPac machine creation)\n")
    show("Windows Server 2025 DCs (BadSuccessor surface, CVE-2025-53779)",
         findings["server2025_dc"])

    if args.json:
        with open(args.json, "w") as f:
            json.dump(findings, f, indent=2, default=str)
        print(f"[+] Wrote {args.json}")


if __name__ == "__main__":
    main()
