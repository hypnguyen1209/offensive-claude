# PPL — Protected Process Light Boundary

PPL is the boundary that protects critical/AV processes from even SYSTEM. It is the wall in
front of LSASS credential theft (`RunAsPPL`) and EDR self-defense (PPL-Antimalware). This
cluster covers how PPL works and the 2023-2026 ways to defeat it *without* a vulnerable
kernel driver (BYOVDLL, live-dump, WER) plus the BYOVD fallback.

## Theory / Mechanism

A process's protection is the `PS_PROTECTION` byte in `EPROCESS` = `Type` (PP vs PPL) +
`Signer` level. Signer levels, high→low: **WinSystem > WinTcb > Windows > Lsa >
Antimalware > Authenticode**. A process may only open another protected process with full
access if its own signer level is **≥** the target's. Consequences for an attacker holding
SYSTEM but no protection:

- `OpenProcess` with `PROCESS_VM_READ`/`VM_WRITE`/`CREATE_THREAD` → access denied.
- `ReadProcessMemory` / `MiniDumpWriteDump` / `CreateRemoteThread` / debugging → denied.

So dumping LSASS (PPL-Lsa) or tampering with an EDR (PPL-Antimalware) needs one of:

### 1. BYOVDLL — "Ghost in the PPL" (no kernel driver) — itm4n
PPL verifies a loaded DLL is **Microsoft-signed**, but **not that it is the current
version**. Replace a current DLL with an **older, still-catalog-signed, vulnerable** one;
PPL loads it and its exploitable code path runs *inside* the PPL context. itm4n's chain
targets the CNG Key Isolation path inside LSASS:

- `keyiso.dll` — **CVE-2023-28229** (UAF in KeyIso) / **CVE-2023-36906** (OOB read).
- `ncryptprov.dll` (Microsoft Software KSP) — loadable **without a reboot** by registering
  a custom Key Storage Provider via the undocumented `BCryptRegisterProvider`
  (from `bcrypt_provider.h`), then opening it (`NCryptOpenStorageProvider`) so LSASS/CNG
  loads the attacker-pointed (vulnerable) DLL into its PPL.

`ppl_byovdll.c` implements the staging half: register a KSP name pointing at the chosen
provider DLL, trigger the load, and unregister for cleanup. The CVE exploit itself runs
from a payload DLL inside the resulting PPL context.

### 2. Live kernel dump via `NtSystemDebugControl` (Win11 23H2+) — slowerzs
Win11 23H2 introduced `LivedumpProcessFiltering`: a user-mode caller with
**`SeDebugPrivilege`** can call `NtSystemDebugControl` with `IncludeUserSpaceMemoryPages`
to produce a kernel **live dump that contains the user-space pages of PPL processes** —
no vulnerable driver needed. From the dump you parse out PPL process memory (e.g.
`services.exe` COM secrets, RPCSS `IRundown` IPID/OXID) and can subsequently invoke
`IRundown::DoCallback` to inject into the PPL target. Affects the specific live-dump
filtering behavior introduced on Win11 23H2.

### 3. WER / minidump-broker on modern Win11 — zerosalarium (2025)
"Old but gold": abuse **Windows Error Reporting** to have a trusted broker generate the
process dump on your behalf, sidestepping the direct `OpenProcess` denial against
PPL-Lsa LSASS.

### 4. BYOVD kernel-write to clear `EPROCESS.Protection` (fallback)
With kernel R/W (see `byovd-kernel-rw.md`), zero the target's `PS_PROTECTION` byte. The
process is now unprotected, so a *normal* `OpenProcess`/`MiniDumpWriteDump`/Mimikatz
`sekurlsa::logonpasswords` works. **Restore the byte afterward** to avoid leaving a
critical process in an inconsistent state. `byovd_kernel_rw.c ppl <pid>` documents this.

### 5. Userland exploit inside a PPL process
A DLL-hijack or logic bug *in* a PPL process gives execution within the PPL context, from
which its own memory is fully accessible (BYOVDLL is a specialized instance of this).

## Modern 2024-2026 Variants (verified)

- **CVE-2023-28229** / **CVE-2023-36906** — the keyiso/CNG bugs that make BYOVDLL ("Ghost
  in the PPL") work against LSASS without a driver (itm4n).
- **NtSystemDebugControl live-dump** PPL read on **Win11 23H2** (`LivedumpProcessFiltering`)
  — driverless PPL injection/read (slowerzs).
- **WER-based LSASS dump on modern Win11** (zerosalarium, Sep 2025) — broker-mediated dump.
- **PPLBlade** — protected-process dumper that obfuscates the dump and supports remote
  upload, used to evade Defender's LSASS-dump detection while bypassing PPL.
- 2026 EDR-killer context: kernel access via BYOVD bypasses PPL entirely — **PPL offers no
  protection once Ring 0 is owned**; Qilin tooling specifically targets PPL-protected EDR
  processes by zeroing protection from the kernel.

## Complete Workflow

```cmd
:: --- Driverless: BYOVDLL staging against LSASS (CNG KSP) ---
ppl_byovdll.exe register C:\stage\vuln_ncryptprov.dll  GhostKsp
ppl_byovdll.exe trigger  GhostKsp        :: LSASS loads the old (vulnerable) DLL into PPL
:: ... run the CVE-2023-28229/36906 payload DLL inside the PPL context ...
ppl_byovdll.exe unregister GhostKsp      :: cleanup KSP registration

:: --- Fallback: BYOVD clear Protection, then dump normally ---
byovd_kernel_rw.exe C:\test\driver.sys ppl 712     :: 712 = lsass PID
:: now a normal dump works:
rundll32 C:\Windows\System32\comsvcs.dll, MiniDump 712 C:\t\out.dmp full
```

Check whether LSASS is even PPL first (`enum_boundaries.ps1` reports `RunAsPPL`):

```powershell
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa').RunAsPPL
```

## Detection

```yaml
title: PPL Bypass / LSASS Access Indicators
id: a31f0c77-2e94-4b6d-9f10-pplbyp001
logsource: { product: windows }
detection:
  lsass_access:                        # Sysmon EID 10
    EventID: 10
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess:
      - '0x1010'   # PROCESS_VM_READ|QUERY_LIMITED
      - '0x1410'
      - '0x1438'
      - '0x143a'
  ksp_dll_load:                        # Sysmon EID 7 inside lsass
    EventID: 7
    Image|endswith: '\lsass.exe'
    ImageLoaded|endswith: ['\ncryptprov.dll', '\keyiso.dll']
    # alert when the loaded version is OLDER than the OS build's shipped version
  livedump:                            # 4688/Sysmon 1
    EventID: 1
    CommandLine|contains: 'IncludeUserSpaceMemoryPages'
  condition: lsass_access or ksp_dll_load or livedump
level: high
```

- **Old DLL version inside LSASS** (Sysmon EID 7 ImageLoad of `keyiso.dll`/`ncryptprov.dll`
  whose file version < the OS-shipped version) is the BYOVDLL tell — version-mismatch is the
  IOC, not the load itself.
- **`HKLM\...\Cryptography\Providers` writes** (KSP registration) from a non-installer
  process.
- **Sysmon EID 10** access to `lsass.exe` with read/dump access masks (Defender, Elastic,
  and most EDRs ship this).
- **`NtSystemDebugControl` / live-dump** invocation and large kernel dump files appearing
  (`MEMORY.DMP`-style) outside crash scenarios.
- **`EPROCESS.Protection` flips to 0** on a critical process — a kernel-callback / EDR
  self-integrity check can flag it; once it is 0 the EDR may already be blinded.

## OPSEC

- **What it touches**: BYOVDLL registers a provider in HKLM and triggers an ImageLoad in
  LSASS (no driver, no `OpenProcess` against PPL). Live-dump/WER produce large dump files on
  disk. The Protection-clear path mutates kernel memory.
- **Cleanup**: `ppl_byovdll.c` unregisters the KSP; delete staged DLLs; for the kernel path
  **restore the original `Protection` byte**; delete any dump files and WER artifacts.
- **Evasion**: driverless techniques (BYOVDLL, live-dump, WER) avoid the loud BYOVD service
  + driver-load telemetry entirely and are the preferred 2024-2026 approach against
  mature EDR. Obfuscate dumps (PPLBlade) to dodge content-based LSASS-dump detection.
- **Hard stops**: BYOVDLL is mitigated by Microsoft re-signing / blocklisting the
  vulnerable DLL versions; HVCI + Credential Guard move secrets into VTL1 (LSAIso) where
  even a PPL-context read returns isolated/encrypted material rather than plaintext creds.

## References

- itm4n — "Ghost in the PPL Part 1: BYOVDLL" (keyiso/ncryptprov, CVE-2023-28229 /
  CVE-2023-36906, undocumented `BCryptRegisterProvider`).
- slowerzs — "Injecting code into PPL processes without vulnerable drivers on Windows 11"
  (`NtSystemDebugControl` `IncludeUserSpaceMemoryPages`, IRundown::DoCallback).
- zerosalarium — "Dumping LSASS with WER on modern Windows 11" (Sep 2025).
- tastypepperoni — **PPLBlade** protected-process dumper + Defender LSASS-dump bypass.
- Tactical Adversary / CyberAdvisors — "Bypass LSA Protection" credential-dumping series.
