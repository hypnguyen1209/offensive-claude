# BYOVD — Bring Your Own Vulnerable Driver (Kernel R/W without an 0-day)

BYOVD loads a legitimately **signed but vulnerable** kernel driver, then abuses its
unauthenticated IOCTLs for a kernel read/write primitive — reaching Ring 0 without
finding a fresh kernel bug. In 2024-2026 this is the dominant kernel-access technique in
ransomware and EDR-killer tooling because it does not require an exploit dev: the bug is
already shipped and signed by a vendor.

## Theory / Mechanism

1. **Drop + load**: write a signed `.sys` to disk, create a kernel service
   (`SERVICE_KERNEL_DRIVER`), `StartService`. Windows loads it because the signature is
   valid — vulnerability state is not checked at load time.
2. **Open the device**: `CreateFile("\\.\<DeviceName>", GENERIC_READ|GENERIC_WRITE)`.
3. **Abuse the IOCTL primitive**. Common shipped primitives:
   - **Physical memory R/W** via `MmMapIoSpace` (e.g. RTCore64.sys, dbutil_2_3.sys).
   - **MSR R/W** via `__readmsr`/`__writemsr` exposed by IOCTL (e.g. LnvMSRIO.sys).
   - **Virtual R/W** / `ZwMapViewOfSection` of `\Device\PhysicalMemory`.
4. **Escalate** with the same EPROCESS techniques as `kernel-user-boundary.md` (token
   steal / `Protection` clear / privilege bits).

### MSR-LSTAR code execution (the modern reliable path)

Because the **PTE self-map for physical→virtual translation was removed on Win11 24H2+**,
brute-forcing the physical address of `EPROCESS` is now unreliable (mis-guesses bugcheck).
The robust alternative when you only have MSR R/W:

- Write the `LSTAR` MSR (`0xC0000082`) — which holds the address of `KiSystemCall64`, the
  SYSCALL entry point — to point at an attacker-staged kernel gadget/payload.
- Any subsequent syscall (from any thread) now executes the payload in Ring 0; the payload
  walks `ActiveProcessLinks` for PID 4, copies the System token, then **restores `LSTAR`**.

This is exactly the chain Quarkslab demonstrated against Lenovo `LnvMSRIO.sys`
(**CVE-2025-8061**, four IOCTLs with no access control: phys R/W + MSR R/W; token stolen
by copying `EPROCESS.Token` at offset `0x248` on their target build). `byovd_kernel_rw.c`
implements the service-load, MSR-write, and `SystemHandleInformation` EPROCESS-leak
skeleton with the LSTAR path documented inline.

## Modern 2024-2026 Variants (verified)

The EDR-killer ecosystem has industrialized driver rotation against Microsoft's
twice-yearly blocklist. Verified recent drivers/CVEs:

| Driver | CVE | Source/role |
|--------|-----|-------------|
| `LnvMSRIO.sys` (Lenovo) | **CVE-2025-8061** | phys + MSR R/W; Quarkslab LSTAR chain |
| `K7RKScan.sys` (K7) | **CVE-2025-52915**, **CVE-2025-1055** | BlackSnufkin BYOVD research repo |
| `PCTcore64.sys` (PC Tools) | **CVE-2026-8501** | same repo |
| `STProcessMonitor.sys` (Safetica) | **CVE-2025-70795** | EDR-kill candidate |
| `xhunter1.sys` (Wellbia, legacy) | **CVE-2026-3609** | legacy anti-cheat driver |
| `NSecKrnl.sys` (NsecSoft) | **CVE-2025-68947** | bundled inside *Reynolds* ransomware (Feb 2026) to kill CrowdStrike/Cortex/Sophos/Symantec/Avast |
| IObit driver | **CVE-2025-26125** | exploited by openly-published *VEN0m* ransomware; not on blocklist as of test on Win11 24H2 |
| `wsftprm.sys` (Topaz Antifraud) | **CVE-2023-52271** | loads on fully-patched Win11 with Secure Boot + HVCI; not blocklisted |

Tooling/landscape: **EDRKillShifter** (originally RansomHub) is now shared across ≥8
ransomware groups (Blacksuit, RansomHub, Medusa, Qilin, Dragonforce, Crytox, Lynx, INC).
By March 2026 researchers counted **54 distinct EDR-killer tools abusing 35 signed
drivers**. Qilin/Warlock maintain *rotating curated driver pools* to stay ahead of the
blocklist. Even **revoked-certificate** drivers (a revoked EnCase forensic driver, Feb 2026)
still loaded.

## Complete Workflow

```cmd
:: 0. Pick a driver still absent from DriverSiPolicy.p7b and (if HVCI on) HVCI-compatible.
::    Cross-check candidate hash against loldrivers.io before use.

:: 1. Load + escalate (token-steal mode) — supply YOUR authorized driver + its IOCTLs
byovd_kernel_rw.exe C:\test\LnvMSRIO.sys token

:: 2. Or clear PPL on lsass so a normal dump works (then dump from a separate tool)
byovd_kernel_rw.exe C:\test\LnvMSRIO.sys ppl 712     :: 712 = lsass PID
```

Check the host's BYOVD posture first (blocklist + HVCI state) with
`enum_boundaries.ps1` — it reports `VulnerableDriverBlocklistEnable`, the
`driversipolicy.p7b` date, and HVCI status, and flags any driver already loaded from a
user-writable path.

## Detection

The detection window is **at driver-load time** — once the EDR's kernel callbacks are
zeroed the box goes dark, so post-hoc detection fails.

```yaml
title: BYOVD - Vulnerable Driver Load From Unusual Path / Known-Bad Hash
id: 2f7c9a51-1e88-4b30-bf42-byovd0001
logsource: { product: windows, category: driver_load }   # Sysmon EID 6
detection:
  unusual_path:
    ImageLoaded|contains:
      - '\Users\'
      - '\Temp\'
      - '\AppData\'
      - '\ProgramData\'
      - '\Public\'
  known_drivers:
    ImageLoaded|endswith:
      - '\RTCore64.sys'
      - '\dbutil_2_3.sys'
      - '\LnvMSRIO.sys'
      - '\NSecKrnl.sys'
      - '\wsftprm.sys'
      - '\xhunter1.sys'
  condition: unusual_path or known_drivers
level: high
```

Additional telemetry:
- **Service creation**: System EID **7045** / Security **4697** with
  `ServiceType=kernel driver` and an image path in a user-writable dir.
- **Sysmon EID 6** logs every driver load with hash + signed flag — primary surface.
  Legitimate drivers load from `%SystemRoot%\System32\drivers`; anything else is a flag.
- **Loss of EDR telemetry**: a sensor that was emitting events suddenly going silent on a
  live host correlates with kernel-callback removal.
- Cross-reference loaded-driver hashes against **loldrivers.io** / threat-intel feeds.

## OPSEC

- **What it touches**: a `.sys` on disk, a registry service key under
  `HKLM\SYSTEM\CurrentControlSet\Services\<svc>`, an `ImageLoad`, and (when killing EDR)
  modified kernel-callback arrays.
- **Cleanup**: stop + `DeleteService`, delete the `.sys`, and **restore any kernel state**
  you changed (LSTAR, callback arrays, `Protection` bytes). Leaving LSTAR hijacked or a
  callback nulled will bugcheck or corrupt the host. `byovd_kernel_rw.c` calls
  `unload_driver()` on exit.
- **Evasion**: prefer a **brand-new, un-blocklisted** driver or a **HVCI-compatible** one;
  legacy 2013-2016 drivers lack CFG and exploit easily but are more likely blocklisted.
  Loading from `%SystemRoot%\System32\drivers` (requires write there) avoids the
  user-writable-path heuristic. Some operators avoid disk by exploiting an
  **already-loaded** vendor driver instead of dropping one.
- **Hard stops**: HVCI + Secure Boot can refuse drivers independent of the blocklist;
  WDAC policy can allow-list driver hashes. Microsoft's blocklist (enabled by default with
  Smart App Control / memory integrity) blocks the well-known set.

## References

- Quarkslab — "BYOVD to the next level (part 1): exploiting Lenovo driver CVE-2025-8061".
- BlackSnufkin/BYOVD GitHub research repo (CVE-2025-52915, CVE-2025-1055, CVE-2026-3609,
  CVE-2026-8501).
- Picus Security / Bitdefender TechZone / Halcyon — BYOVD explainers + EDRKillShifter spread.
- MINE2 — "EDR Killers 2026" (54 tools / 35 drivers; Reynolds ransomware + CVE-2025-68947).
- zerosalarium — "BYOVD to the next level: Blind EDR with Windows Symbolic Link".
- loldrivers.io — community vulnerable-driver database for hash cross-referencing.
