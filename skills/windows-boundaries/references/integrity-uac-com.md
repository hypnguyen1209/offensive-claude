# Integrity Levels, UAC & COM Elevation Boundaries

Windows mandatory integrity control (MIC) ranks processes Untrusted → Low → Medium → High
→ System. UAC mediates the **Medium → High** transition for administrators. Microsoft
states UAC is **not a security boundary**, but crossing Medium→High silently is a core LPE
step (and crossing Low→Medium genuinely is a boundary). This cluster covers the integrity
model and the COM/registry techniques that auto-elevate without a consent prompt.

## Theory / Mechanism

| Level | RID | Token SID | Typical occupant |
|-------|-----|-----------|------------------|
| System | 0x4000 | S-1-16-16384 | services, SYSTEM |
| High | 0x3000 | S-1-16-12288 | elevated admin |
| Medium | 0x2000 | S-1-16-8192 | standard user / unelevated admin |
| Low | 0x1000 | S-1-16-4096 | Protected-Mode, some sandboxes |
| Untrusted | 0x0000 | S-1-16-0 | AppContainer |

**UAC internals**: `appinfo.dll` (the AppInfo service) handles elevation over RPC. An EXE
auto-elevates if it (1) has `autoElevate=true` in its manifest, (2) passes a `WinVerifyTrust`
signature check, and (3) lives in a *secure* directory (`C:\Windows\System32`). Auto-
elevating binaries: `fodhelper.exe`, `computerdefaults.exe`, `sdclt.exe`, `slui.exe`,
`eventvwr.exe`, `cmstp.exe`, `wsreset.exe`, `changepk.exe`, `WSReset.exe`.

Two abuse families:

### (a) Registry-hijack auto-elevate (UACME method 33 — fodhelper)
`fodhelper.exe`/`computerdefaults.exe` are auto-elevating and read **HKCU** (writable by
the standard user) when resolving a shell handler. Plant a command under
`HKCU\Software\Classes\ms-settings\Shell\Open\command` (with an empty `DelegateExecute`
value to force the command branch), launch `fodhelper.exe`, and the value runs at High
integrity — no prompt. `uac_com_elevate.cpp` mode `fod` implements this and cleans the key.

### (b) Elevated COM moniker (UACME method 41 — CMSTPLUA / ICMLuaUtil)
The COM class **CMSTPLUA** `{3E5FC7F9-9A51-4367-9063-A120244FBEC7}` is marked
*AutoApproved* + *AutoElevate* in the registry. Binding to it through the moniker
`"Elevation:Administrator!new:{3E5FC7F9-...}"` makes COM host the object in a **High-
integrity `dllhost.exe`** (`/Processid:{...}`). Its **`ICMLuaUtil::ShellExec`** method
(`{6EDD6D74-C007-4E75-B76A-E5740995E24C}`, vtable index 6) then launches any command,
inheriting High integrity. `uac_com_elevate.cpp` mode `com` implements this end-to-end.

## Modern 2024-2026 Variants (verified)

- **IEditionUpgradeManager COM UAC bypass** — published 2025-09-28 (G3tSyst3m); a fresh
  COM-object auto-elevation in the same family as ICMLuaUtil, reported to still work on
  current builds (code needs editing "to make EDR happy"). The pattern: find a COM class
  with `AutoElevate`/`AutoApproved` exposing a method that runs code (ShellExec-style).
- **Microsoft deprecated several older bypasses in a March 2025 update**, but researchers
  resurrected an older method with tweaks — the class of bug (HKCU-read auto-elevate +
  COM auto-approve) is durable even as individual CLSIDs get hardened.
- **Active in-the-wild use of T1548.002 in 2025**: Earth Kasha (Taiwan/Japan campaign,
  Apr 2025); DPRK Kimsuky *HttpTroy* and Lazarus *BLINDINGCAN* variant (Oct 2025) per
  MITRE ATT&CK references.

Note: ICMLuaUtil/CMSTPLUA and fodhelper are *publicly known since ~2016/2017* and are
mitigated at UAC level "Always Notify" (level 4). They remain effective at the **default**
UAC level on Win10/11 for an admin user. Hunting for new `AutoElevate` COM classes
(OleViewDotNet) is the way to find currently-undetected variants.

## Complete Workflow

```cmd
:: COM moniker path (no file dropped; spawns High-integrity dllhost child)
uac_com_elevate.exe com "C:\Windows\System32\cmd.exe /c whoami /groups > C:\poc.txt"

:: fodhelper registry path (writes+cleans HKCU ms-settings)
uac_com_elevate.exe fod "C:\Windows\System32\cmd.exe"
```

Discover new AutoElevate COM classes (PowerShell + OleViewDotNet / NtObjectManager):

```powershell
Import-Module OleViewDotNet
Get-ComClass | Where-Object {
    $_.AppIdEntry -and ($_.AppIdEntry.AutoApprovalElevation -or $_.AppIdEntry.Flags -match 'Elevate')
} | Select Clsid, Name, AppId
```

Confirm integrity transition:

```cmd
whoami /groups | findstr "Mandatory"   :: before
:: ... run bypass ...
:: target child should show: Mandatory Label\High Mandatory Level
```

## Detection

```yaml
title: UAC Bypass - fodhelper/ICMLuaUtil Elevated COM
id: 4d1a77c2-9b6e-44f0-8c01-uaccom001
logsource: { product: windows }
detection:
  fodhelper_reg:                       # Sysmon EID 13
    EventID: 13
    TargetObject|contains: '\Software\Classes\ms-settings\Shell\Open\command'
  fodhelper_proc:                      # Sysmon EID 1 / 4688
    Image|endswith: ['\fodhelper.exe', '\computerdefaults.exe']
    ParentImage|endswith: ['\explorer.exe', '\cmd.exe', '\powershell.exe']
  icmluautil:                          # dllhost spawned then a shell child
    ParentImage|endswith: '\dllhost.exe'
    ParentCommandLine|contains: '/Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}'
    Image|endswith: ['\cmd.exe', '\powershell.exe', '\rundll32.exe']
  condition: fodhelper_reg or fodhelper_proc or icmluautil
level: high
```

- **fodhelper**: the registry write to `HKCU\...\ms-settings\Shell\Open\command`
  (Sysmon EID 13) is the highest-fidelity IOC — even if the payload is obfuscated, the
  value reveals the command. Elastic and ManageEngine ship rules for both.
- **ICMLuaUtil**: a `dllhost.exe /Processid:{3E5FC7F9-...}` parent spawning a shell/LOLBin
  child (Elastic "UAC Bypass via ICMLuaUtil Elevated COM Interface").
- Integrity flip: a child process at High integrity whose parent was Medium with no
  `consent.exe` (UAC prompt) interaction.

## OPSEC

- **What it touches**: COM path is fileless but spawns a visible `dllhost.exe` →
  shell child genealogy. fodhelper path writes HKCU registry (transient if cleaned).
- **Cleanup**: `uac_com_elevate.cpp` removes the `HKCU\Software\Classes\ms-settings` tree
  after triggering. For COM, prefer calling an in-process action over `cmd.exe`.
- **Evasion**: rotate to a less-monitored AutoElevate CLSID (IEditionUpgradeManager and
  others) since EDR signatures key on the well-known CMSTPLUA GUID and the `ms-settings`
  registry path. Avoid spawning `cmd`/`powershell` from `dllhost` — call a method that
  performs the action directly, or use a custom proxy DLL.
- **Hard stop**: UAC "Always Notify" defeats auto-elevation; these are not boundaries —
  treat them as convenience LPE, not stealthy persistence, in mature-EDR environments.

## References

- UACME project (hfiref0x) — canonical catalog; methods 33 (fodhelper) and 41 (ICMLuaUtil).
- G3tSyst3m — "Creative UAC Bypass Methods for the Modern Era" (Mar 2025) and the
  IEditionUpgradeManager COM bypass (Sep 2025).
- Elastic Security — "UAC Bypass via ICMLuaUtil Elevated COM Interface" detection rule.
- MITRE ATT&CK T1548.002 — references incl. Earth Kasha, Kimsuky HttpTroy, Lazarus
  BLINDINGCAN (2025).
- CQURE Academy — "How UAC bypass methods really work" (appinfo.dll / autoElevate internals).
