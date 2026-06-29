# Kernel / User Boundary Crossing

The kernel/user (Ring 0 / Ring 3) boundary is the most consequential Windows security
boundary: a kernel R/W primitive defeats every userland control above it — integrity
levels, AppContainer, PPL, EDR userland hooks. This cluster covers reaching Ring 0 via
the native kernel attack surface (syscalls into `win32k`/`dxgkrnl`, third-party driver
IOCTLs) and converting a memory-corruption bug into SYSTEM.

## Theory / Mechanism

Ring 3 reaches Ring 0 through a fixed set of gates:

- **Syscalls** into `ntoskrnl.exe` and the GUI subsystem `win32k.sys` / `win32kfull.sys`.
  `win32k` is historically the richest LPE surface because it exposes hundreds of syscalls
  reachable from a desktop process and manages complex stateful objects (windows, DCs,
  brushes, fonts) prone to UAF and type confusion.
- **Graphics kernel** `dxgkrnl.sys` / DirectX: reachable from low-privilege contexts
  (document preview, thumbnailing, RDP rendering, browser GPU process) which makes its
  UAFs attractive sandbox-aware LPE bugs.
- **Driver IOCTLs**: `DeviceIoControl` to a driver's device object. `METHOD_NEITHER`
  IOCTLs pass user pointers straight to the driver — the classic unauthenticated
  arbitrary-R/W surface that BYOVD relies on (see `byovd-kernel-rw.md`).

A kernel bug yields one of two primitives, which are then escalated identically:

1. **Arbitrary read** → defeat KASLR: leak `ntoskrnl` base, resolve `PsInitialSystemProcess`
   / `PsActiveProcessHead`, walk `EPROCESS`.
2. **Arbitrary write (write-what-where)** → choose a target:
   - **Token steal**: copy System process (`PID 4`) `EPROCESS.Token` into the attacker's
     `EPROCESS.Token`. Simplest, instantly SYSTEM.
   - **Privilege bits**: OR `0xFFFFFFFFFFFFFFFF` into `EPROCESS.Token`'s
     `SEP_TOKEN_PRIVILEGES.Present/Enabled`.
   - **`EPROCESS.Protection` clear**: zero the `PS_PROTECTION` byte to strip PPL
     (see `ppl-protected-process.md`).
   - **`PreviousMode`**: set the thread's `KTHREAD.PreviousMode` to `KernelMode (0)` so
     `Nt*` calls skip user-pointer probing — a self-sustaining R/W via `NtReadVirtualMemory`.

Resolving offsets: `EPROCESS` layout changes every build. Resolve dynamically — leak
`ntoskrnl` base via `NtQuerySystemInformation(SystemModuleInformation)`, parse exports, or
derive offsets from the running build. The script `ioctl_fuzzer.py` maps a driver's IOCTL
surface; `byovd_kernel_rw.c` shows the EPROCESS-walk + token-copy skeleton.

## Modern 2024-2026 Variants (verified)

| CVE | Component | Class | Notes |
|-----|-----------|-------|-------|
| **CVE-2025-24983** | `win32k` | Use-after-free | Patched March 2025 Patch Tuesday; **exploited in the wild** (ESET-reported), LPE to SYSTEM via UAF in window objects. CVSS 7.0. |
| **CVE-2025-62573** | `dxgkrnl` (DirectX Graphics Kernel) | UAF / race | EoP, local vector, CVSS 7.0. Graphics kernel reachable via preview/thumbnail/RDP. |
| **CVE-2025-55224** | `win32k` GRFX | Race condition | Local EoP; timing-win exploitable via thread affinity / scheduler stress. |
| **CVE-2025-62221** | `cldflt.sys` (Cloud Files mini-filter) | UAF | LPE to SYSTEM; mini-filter drivers are a recurring 2025 EoP surface. |
| **CVE-2026-26132** | Windows Kernel | UAF | 2026 Patch-Tuesday priority kernel UAF (per public trackers). |

Modern constraint to know: on recent kernels (Win11 24H2+) the **PTE self-map used to
translate arbitrary physical→virtual addresses is no longer available**, so exploits that
relied on a physical-memory R/W primitive can no longer brute-force the physical address of
`EPROCESS`. Reliable chains now resolve `EPROCESS` via a leaked kernel pointer
(`SystemHandleInformation`) or pivot through MSR/virtual primitives instead (see
`byovd-kernel-rw.md`).

## Complete Workflow

```cmd
:: 1. Map a target driver's IOCTL surface; flag METHOD_NEITHER (arbitrary-RW risk)
python ioctl_fuzzer.py --device RTCore64 --map

:: 2. Fuzz the risky codes to confirm a read/write primitive
python ioctl_fuzzer.py --device RTCore64 --fuzz --iterations 5000
```

EPROCESS token-steal payload logic (the part that runs once you have kernel R/W):

```c
// pseudo-C for the kernel-write primitive (offsets are build-specific, resolve them)
UINT64 ps_head   = nt_base + OFF_PsActiveProcessHead;   // from SystemModuleInformation
UINT64 cur = kread64(ps_head);                          // first EPROCESS link
UINT64 sys_token = 0, my_eproc = 0;
do {
    UINT64 eproc = cur - OFF_ActiveProcessLinks;        // ListEntry -> EPROCESS
    UINT64 pid   = kread64(eproc + OFF_UniqueProcessId);
    if (pid == 4)             sys_token = kread64(eproc + OFF_Token);   // System
    if (pid == GetCurrentProcessId()) my_eproc = eproc;                 // us
    cur = kread64(cur);
} while (cur != ps_head);
kwrite64(my_eproc + OFF_Token, sys_token & ~0xF);       // copy token (mask ref count)
// current process is now SYSTEM
```

WinDbg offset discovery on the matching build:

```
dt nt!_EPROCESS UniqueProcessId Token ActiveProcessLinks Protection
?? @@C++(&((nt!_EPROCESS*)0)->Token)
```

## Detection

Kernel exploitation surfaces in three places: the bug trigger, the post-exploitation
write, and the (frequent) bugcheck on a failed attempt.

```yaml
title: win32k/dxgkrnl Exploit Indicators - Crash + Suspicious Token
id: 8b9d1f02-3c44-4f7a-9d2e-kernuser01
logsource: { product: windows }
detection:
  bugcheck:
    EventLog: System
    Provider: 'Microsoft-Windows-WER-SystemErrorReporting'
    EventID: 1001
    Data|contains:
      - 'win32kfull.sys'
      - 'win32k.sys'
      - 'dxgkrnl.sys'
      - 'cldflt.sys'
  token_anomaly:        # EDR-side: a non-SYSTEM process suddenly running as SYSTEM
    selection_proc:
      EventID: 4688
      TokenElevationType: '%%1937'   # full token
  condition: bugcheck or token_anomaly
level: high
```

EDR telemetry that matters:
- **PsSetCreateProcessNotifyRoutine** sees a process whose token SID flips to S-1-5-18 with
  no `runas`/service genealogy — strong post-exploitation IOC for token steal.
- Repeated **bugchecks (0x3B SYSTEM_SERVICE_EXCEPTION, 0x50, 0xA)** referencing `win32k`/
  `dxgkrnl` from the same user session = exploit attempts (fuzzing/heap-groom misses).
- ETW `Microsoft-Windows-Win32k` provider: anomalous syscall sequences / object lifetime.
- IOCTL storms to one device handle (thousands of `DeviceIoControl` with `METHOD_NEITHER`).

## OPSEC

- **What it touches**: a successful token steal mutates kernel memory only; nothing on
  disk. The risk is the *trigger* — heap grooming spawns many objects, and a missed race
  bugchecks the box (very loud: minidump + EID 1001 + reboot).
- **Mitigations in the way**: HVCI does not stop a pure data-only `EPROCESS` write, but
  **KDP (Kernel Data Protection)** marks some structures read-only; **Hypervisor-enforced
  PatchGuard** and **VBS** raise the bar for code-execution-style kernel exploits. `win32k`
  syscall filtering (per-process win32k lockdown, used by browsers/AppContainers) shrinks
  the surface — but `dxgkrnl` and many driver IOCTLs remain reachable.
- **Cleanup**: if you set `PreviousMode`/`Protection`, restore the original byte before
  exiting to avoid leaving a process in an inconsistent protected state that triggers later
  bugchecks. Token steal needs no cleanup but the elevated child is the visible artifact —
  prefer reflective in-process action over spawning `cmd.exe`.
- **Reliability**: prefer data-only primitives (token copy) over control-flow hijack on
  HVCI/CET hosts; ROP/CFG bypass in the kernel is far harder than a `kwrite64`.

## References

- Microsoft Security Update Guide — CVE-2025-24983, CVE-2025-62573, CVE-2025-55224,
  CVE-2025-62221, CVE-2026-26132 (advisories).
- ESET / Unit 42 — "Inside Win32k Exploitation" analysis (CVE-2022-21882 / CVE-2021-1732
  methodology, still the canonical UAF-to-token-steal walkthrough).
- Quarkslab — "BYOVD to the next level (part 1): exploiting Lenovo driver CVE-2025-8061"
  (the modern no-PTE-self-map constraint and the `SystemHandleInformation` EPROCESS leak).
- Connor McGarr / various — EPROCESS token-stealing primitive write-ups.
