#!/usr/bin/env python3
"""
net_service_scan.py - Targeted network-service exposure scanner for known
high-impact Windows network RCEs. Fingerprints whether the *vulnerable surface*
is reachable (the service is listening) and maps it to the relevant CVE +
nmap NSE / safe check. Does NOT exploit; it scopes and prioritizes.

USAGE:
    python3 net_service_scan.py 10.0.0.0/24
    python3 net_service_scan.py 10.0.0.5 --json out.json

DEPENDENCIES: Python 3.8+ stdlib only (raw socket connect scan).
    Optional: nmap in PATH for the deeper version/NSE follow-ups it prints.

COVERAGE (verified 2024-2025 CVEs):
  445   SMB        -> MS17-010 EternalBlue (legacy), CVE-2025-33073 reflection
  3389  RDP/RDS    -> CVE-2025-24035 / CVE-2025-24045 (RDS RCE, Mar 2025)
  135   RPC/EPM    -> coercion surface (MS-RPRN/EFSR/DFSNM) + NEGOEX CVE-2025-47981
  1688  RD Licensing(MadLicense CVE-2024-38077 pre-auth heap overflow, CVSS 9.8)
  Multicast(RMCAST)-> CVE-2025-21307 (wormable; not a TCP port, advisory only)
"""
import argparse
import concurrent.futures
import ipaddress
import json
import socket
import shutil

# port -> (service, [(cve, note, followup)])
CHECKS = {
    445: ("SMB", [
        ("MS17-010", "EternalBlue (legacy 2008/7/2012)",
         "nmap -p445 --script smb-vuln-ms17-010 {ip}"),
        ("CVE-2025-33073", "NTLM reflection -> SYSTEM if SMB signing not enforced (Jun 2025)",
         "nxc smb {ip}   # check Signing:False, then coerce+reflect"),
    ]),
    3389: ("RDP/RDS", [
        ("CVE-2025-24035", "RDS RCE (Mar 2025, CVSS 8.1)",
         "nmap -p3389 --script rdp-ntlm-info,rdp-enum-encryption {ip}"),
        ("CVE-2025-24045", "RDS RCE (Mar 2025)", "verify patch level via WSUS/SCCM"),
        ("CVE-2019-0708",  "BlueKeep (legacy 7/2008R2)",
         "nmap -p3389 --script rdp-vuln-ms12-020 {ip}"),
    ]),
    135: ("MSRPC/EPM", [
        ("coercion", "MS-RPRN/MS-EFSR/MS-DFSNM coercion endpoints",
         "impacket-rpcdump {ip} | grep -iE 'spool|efs|netdfs'"),
        ("CVE-2025-47981", "NEGOEX/SPNEGO wormable pre-auth RCE (Jul 2025, CVSS 9.8)",
         "patch check: KB for Windows 10 1607+ / Server"),
    ]),
    1688: ("RD-Licensing", [
        ("CVE-2024-38077", "MadLicense pre-auth heap overflow -> RCE, CVSS 9.8 "
                           "(all Server 2000-2025 with RDL role)",
         "service should NOT be internet-facing; patch Aug 2024"),
    ]),
    5985: ("WinRM", [
        ("relay/PtH", "WinRM relay & pass-the-hash lateral movement target",
         "evil-winrm -i {ip} -u <u> -H <ntlm>"),
    ]),
    1433: ("MSSQL", [
        ("relay/xp_cmdshell", "ntlmrelayx mssql target + xp_cmdshell RCE",
         "impacket-ntlmrelayx -t mssql://{ip} -q \"EXEC xp_cmdshell 'whoami'\""),
    ]),
}


def scan_host(ip, ports, timeout=2.0):
    open_ports = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
        except OSError:
            pass
        finally:
            s.close()
    return ip, open_ports


def main():
    ap = argparse.ArgumentParser(description="Map exposed Windows RCE surfaces.")
    ap.add_argument("cidr", help="subnet or single IP")
    ap.add_argument("--json", help="write findings JSON")
    ap.add_argument("--threads", type=int, default=64)
    ap.add_argument("--timeout", type=float, default=2.0)
    args = ap.parse_args()

    try:
        net = ipaddress.ip_network(args.cidr, strict=False)
        hosts = [str(h) for h in net.hosts()] if net.num_addresses > 1 else [str(net.network_address)]
    except ValueError:
        hosts = [args.cidr]

    ports = list(CHECKS.keys())
    print(f"[*] Scanning {len(hosts)} hosts x {len(ports)} ports ...")
    findings = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = [ex.submit(scan_host, h, ports, args.timeout) for h in hosts]
        for fut in concurrent.futures.as_completed(futs):
            ip, open_ports = fut.result()
            if not open_ports:
                continue
            for p in open_ports:
                svc, cves = CHECKS[p]
                print(f"\n[+] {ip}:{p}/tcp {svc} OPEN")
                for cve, note, followup in cves:
                    print(f"      {cve:18s} {note}")
                    print(f"        > {followup.format(ip=ip)}")
                    findings.append({"ip": ip, "port": p, "service": svc,
                                     "cve": cve, "note": note})

    if not any(f for f in findings):
        print("[i] no target services reachable")
    print("\n[i] RMCAST CVE-2025-21307 (wormable) has no fixed TCP port; "
          "verify patch level on multicast-enabled hosts.")
    if not shutil.which("nmap"):
        print("[i] nmap not in PATH; install for the NSE follow-up checks above.")

    if args.json:
        with open(args.json, "w") as fh:
            json.dump(findings, fh, indent=2)
        print(f"[+] findings -> {args.json}")


if __name__ == "__main__":
    main()
