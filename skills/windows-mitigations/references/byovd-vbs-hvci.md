# BYOVD + VBS / HVCI / Credential Guard + Kernel Shadow Stack

Cluster on the kernel/platform boundary: **Bring Your Own Vulnerable Driver (BYOVD)** to obtain
ring-0 R/W, the **Microsoft driver blocklist / LOLDrivers / HVCI** controls that try to stop it,
and **Virtualization-Based Security (VBS)** with **Credential Guard** and the **kernel shadow
stack** that limit what ring-0 buys you. This is the loudest, highest-impact path — used only when
userland approaches (acg-cig, ppl-lsa-protection, asr-amsi-etw) are insufficient.

## Theory / Mechanism

```
VTL0 (Normal World)                    VTL1 (Secure World / Secure Kernel)
- NT kernel, drivers, EPROCESS         - HVCI (W^X for kernel: pages can't be both W and X)
- LSASS (creds in VTL0 unless CG)       - Credential Guard: LsaIso enclave holds secrets
- your ring-0 R/W after BYOVD           - KDP: read-only kernel data (e.g. CI g_CiOptions)
                                        - SKCI verifies driver signatures before load
```
Even with full kernel R/W in VTL0 you **cannot** read/write VTL1 memory, and **HVCI** means you
can't make new kernel code executable (no unsigned shellcode in kernel) — which is exactly why
attackers use *signed-but-vulnerable* drivers (BYOVD) for **data-only** kernel manipulation rather
than loading unsigned code.

### Recon — what's enforced?
```powershell
$dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard
$dg.SecurityServicesRunning   # 1=Credential Guard running, 2=HVCI running
$dg.VirtualizationBasedSecurityStatus  # 2 = VBS running
reg query "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity
reg query "HKLM\SYSTEM\CurrentControlSet\Control\CI\Config" /v VulnerableDriverBlocklistEnable
reg query "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks" 2>nul
```

## BYOVD — build a kernel R/W primitive

A signed driver with an unvalidated `MmMapIoSpace` / `ZwMapViewOfSection` / physical-memory IOCTL
gives arbitrary read/write. Classic example, RTCore64.sys (MSI Afterburner): IOCTL `0x80002048`
reads, `0x8000204C` writes via MSR/virtual addresses. Generic flow:
```text
1. Drop signed vulnerable .sys to disk
2. Create + start service:  sc create drv binPath= C:\path\drv.sys type= kernel & sc start drv
   (or NtLoadDriver with a crafted registry service key)
3. CreateFileW("\\\\.\\<DeviceName>") -> DeviceIoControl(<rw IOCTL>) = arbitrary kernel R/W
4. Resolve nt!PsInitialSystemProcess -> walk ActiveProcessLinks
5. Token-steal:  write SYSTEM EPROCESS.Token into your EPROCESS.Token  -> SYSTEM
   or PPL-strip:  zero EPROCESS.Protection of target (see ppl-lsa-protection.md)
   or blind EDR:  remove PsSetCreateProcessNotifyRoutine / Ob callbacks (data-only)
```

## Defeating the driver blocklist / LOLDrivers / HVCI

The 2024–2026 trend: stop using **catalogued** drivers and use a **previously unknown** vulnerable
one. Check Point's **Silver Fox APT** campaign abused `amsdk.sys` (WatchDog Antimalware
v1.0.600, built on the Zemana SDK) — Microsoft-signed, **not** in the Microsoft Vulnerable Driver
Blocklist and **not** in LOLDrivers, yet it grants LPE, raw disk R/W, and **arbitrary process
termination without checking PP/PPL** — a clean EDR/AV killer on fully-patched Win10/11. They
shipped a dual-driver loader (a known Zemana driver for legacy, the undetected WatchDog driver for
modern hosts) bundled with ValleyRAT.

Recent weaponized drivers / CVEs to evaluate (verify still-unblocked on the target build):
`BdApiUtil64.sys` Baidu (CVE-2024-51324), `K7RKScan.sys` K7 (CVE-2025-52915, CVE-2025-1055),
`GameDriverX64.sys` Fedeen Games (CVE-2025-61155), `STProcessMonitor.sys` Safetica
(CVE-2025-70795), `PCTcore64.sys` PC Tools (CVE-2026-8501), `amsdk.sys` WatchDog (Silver Fox).

```bash
# Decide if a candidate driver will (a) load and (b) evade controls on this target
python scripts/check_driver_blocklist.py mydriver.sys \
  --blocklist driversipolicy.json --loldrivers loldrivers.json
# reports: in MS blocklist? in LOLDrivers (by sha256/authentihash)? + HVCI/SecureBoot caveat
```
**HVCI / Secure Boot can block a driver even when the blocklist doesn't** — they enforce stricter
signing/integrity (e.g., reject WHQL-only or hypervisor-incompatible drivers, or page-hash
mismatches). So a driver absent from the blocklist may still fail to load under HVCI. Always test
load on a Secure-Boot+HVCI host before relying on it. Conversely, with **HVCI off** you can also
just load an unsigned driver outright (test-signing / no SKCI gate).

## VBS / HVCI bypass approaches

1. **Data-only kernel attack (recommended under HVCI).** HVCI blocks unsigned *code*, not data
   edits. With BYOVD R/W, modify kernel *data* (tokens, `EPROCESS.Protection`, callbacks) — never
   execute unsigned kernel code, so HVCI is irrelevant. KDP-protected regions (e.g.,
   `g_CiOptions`) are the exception — read-only in VTL1, can't be flipped that way.
2. **Disable VBS via boot config (admin + reboot — loud).**
   ```cmd
   bcdedit /set hypervisorlaunchtype off
   reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f
   :: requires reboot; generates boot-config + DeviceGuard registry change events
   ```
3. **Hypervisor / Secure-Kernel vulnerabilities (rare, high impact).** A guest-to-host or
   VTL0-to-VTL1 escape defeats VBS wholesale; class includes historical Hyper-V vmswitch RCE
   (CVE-2021-28476). Treat as opportunistic, not a reliable engagement primitive.
4. **Side-channel on VTL1.** Spectre-class leakage of enclave secrets — heavily microcode-
   mitigated, generally impractical in an engagement.

## Kernel shadow stack (Win11 24H2)
Kernel-mode Hardware-enforced Stack Protection (KMSSP) extends CET shadow stacks to ring 0,
blocking kernel ROP. Per Synacktiv (SSTIC 2025) it is **not enabled by default** on 24H2 (enable
via Core Isolation or `HKLM\...\DeviceGuard\Scenarios\KernelShadowStacks`, Audit vs Regular).
Implication for BYOVD: prefer **data-only** kernel manipulation (no ROP) so the kernel shadow
stack is never exercised; this is already the recommended HVCI-era technique.

## Detection

```yaml
title: BYOVD - Vulnerable Driver Load and Kernel Tampering
id: f0a1b2c3-d4e5-4f60-9a8b-7c6d5e4f3a2b
status: stable
logsource:
  product: windows
  category: driver_load            # Sysmon EID 6
detection:
  driver:
    ImageLoaded|endswith: '.sys'
    Signature|contains: ['MSI','Zemana','WatchDog','Baidu','K7','Safetica','PC Tools']
  svc_create:                       # Sysmon EID 13 — kernel service key
    TargetObject|contains: '\Services\'
    TargetObject|endswith: '\ImagePath'
    Details|endswith: '.sys'
  condition: driver or svc_create
fields: [ImageLoaded, Signature, Hashes, TargetObject, Details]
falsepositives: [legitimate vendor driver installs, OC/monitoring tools]
level: high
```
IOCs: Sysmon EID 6 driver load whose signer is a third party (not Microsoft) + matching service
ImagePath registry write (EID 13); a `.sys` dropped to a user-writable/temp path then loaded;
`bcdedit hypervisorlaunchtype off` or DeviceGuard registry writes; EDR self-protection /
callback-removal alerts; MDE Advanced Hunting matching the loaded driver hash against LOLDrivers
*and* the Microsoft Vulnerable Driver List. Because the EDR itself may be the victim, **agent
silence** (telemetry stops) is itself a detection — monitor agent health out-of-band.

## OPSEC

- Strongest *prevention* (and your biggest obstacle): HVCI + the Microsoft driver blocklist +
  WDAC kernel allow-list. Confirm their state in recon; if all on, lean on data-only / userland.
- Pick a driver **absent from both** the Microsoft blocklist and LOLDrivers, and verify it loads
  under Secure Boot + HVCI on a matching build before the op — a blocked load is a hard IOC.
- Driver load (EID 6) + service-key write (EID 13) are unavoidable signals; minimize dwell — load,
  do the data-only edit (token steal / PPL strip / callback removal), unload, delete the `.sys`
  and service key. Don't leave the driver resident.
- Disabling VBS via bcdedit requires a reboot and is extremely loud (boot-config + reboot events);
  prefer data-only manipulation that coexists with VBS over turning it off.
- Don't load unsigned kernel code under HVCI — it simply fails and alerts; everything is
  data-only.

## References

- Check Point Research — *Chasing the Silver Fox: Cat & Mouse in Kernel Shadows* (amsdk.sys, unblocked BYOVD, 2025): https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/
- Check Point Research — *Breaking Boundaries: Investigating Vulnerable Drivers* (2024 scale, YARA retrohunt): https://research.checkpoint.com/2024/breaking-boundaries-investigating-vulnerable-drivers-and-mitigating-risks/
- BlackSnufkin — *BYOVD* (weaponized-driver PoCs / recent CVEs): https://github.com/BlackSnufkin/BYOVD
- Microsoft Learn — *Microsoft recommended driver block rules*: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules
- Synacktiv — *Analyzing the Windows kernel shadow stack mitigation* (SSTIC 2025): https://www.synacktiv.com/sites/default/files/2025-06/sstic_windows_kernel_shadow_stack_mitigation.pdf
- Microsoft — *Strategies to monitor and prevent vulnerable driver attacks* (MDE hunting, LOLDrivers+MVDL): https://techcommunity.microsoft.com/blog/microsoftsecurityexperts/strategies-to-monitor-and-prevent-vulnerable-driver-attacks/4103985
