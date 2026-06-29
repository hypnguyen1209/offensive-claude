# Anti-Reversing, Anti-VM & Packer Bypass

Cluster: detecting and neutralizing the protections that stop analysis — anti-debug checks, anti-VM /
sandbox evasion, and runtime packers that hide the real (OEP) code until execution.
ATT&CK: T1622 (Debugger Evasion), T1497 / T1497.001 (Virtualization/Sandbox Evasion: System Checks),
T1497.003 (Time Based Evasion), T1027.002 (Software Packing), T1620 (Reflective/Memory Loading).
CWE: methodology (no single weakness class).

## Theory / Mechanism

**Anti-debug** queries OS state that differs under a debugger (PEB flags, `TracerPid`, debug registers,
exception handling, timing). **Anti-VM** queries the environment for hypervisor/sandbox artifacts
(CPUID hypervisor bit, MAC OUI, device names, low core/RAM, mouse idleness). **Packers** compress/encrypt
the original code and restore it in memory at runtime; the *Original Entry Point* (OEP) is reached after
the unpacking stub finishes — dumping memory at OEP yields the real binary. Bypass = classify each check,
then patch the call / spoof the data / forward the exception / dump after unpack.

## Anti-Debug Taxonomy & Bypass (verified, current)

| Check | How it detects | Bypass |
|-------|----------------|--------|
| `IsDebuggerPresent` / `PEB.BeingDebugged` | reads `gs:[0x60]+2` | zero the PEB byte; ScyllaHide auto |
| `NtGlobalFlag` (PEB+0xBC) | heap flags set under debugger | clear `FLG_HEAP_*` bits in PEB |
| `CheckRemoteDebuggerPresent`/`NtQueryInformationProcess(ProcessDebugPort)` | debug port handle | hook → return 0 / NULL port |
| `NtSetInformationThread(ThreadHideFromDebugger=0x11)` | detaches thread from debugger | hook NtSetInformationThread; or skip call via RIP, or pass class 0 |
| HW breakpoints via `GetThreadContext` (DR0-DR3) | nonzero debug registers | zero Dr0-3 in returned CONTEXT; ScyllaHide hooks GetThreadContext |
| `KiUserExceptionDispatcher` CONTEXT check | kernel copies CONTEXT to stack on exception; sample reads Dr0-3/ContextFlags | patch KiUserExceptionDispatcher (ScyllaHide), or patch the faulting opcode |
| `NtClose(0xDEADC0DE)` invalid handle | exception only raised under debugger | catch/ignore the exception; ScyllaHide |
| `INT 2D` / `INT 3` / `ICEBP(0xF1)` | debugger swallows/handles trap differently | single-step over, fix EIP/EFLAGS |
| `rdtsc` / `GetTickCount` / `QueryPerformanceCounter` timing | execution slower under debugger | spoof monotonic increments (ScyllaHide returns predictable deltas) |
| `NtQuerySystemInformation(SystemKernelDebuggerInformation/Modules)` | kernel debugger / driver names (sice.sys, syser.sys) | hook → strip entries / return clean |
| Linux `ptrace(PTRACE_TRACEME)` | second ptrace fails if traced | LD_PRELOAD hook returning 0, or NOP the call |
| Linux `/proc/self/status` `TracerPid` | nonzero when traced | LD_PRELOAD `open`/`read` filter to zero the field |

> Modern reality: ScyllaHide (user-mode, hooks Nt* + KiUserExceptionDispatcher) clears ~80% of checks
> for x64dbg/IDA/Olly. Hardened packers (VMProtect "Heaven's Gate" 32→64-bit far-jump tricks) can defeat
> user-mode hiding — escalate to **TitanHide/HyperHide** (kernel SSDT hooks). Always harden the analysis
> VM first with **al-khaser** / **InviZzzible** to know what your environment leaks.

## Complete Working Bypass

### 1. Enumerate anti-debug primitives statically (this skill's script)
```bash
python3 scripts/antidebug_unhook.py --scan ./sample
# Greps imports/asm for IsDebuggerPresent, NtSetInformationThread, GetThreadContext, rdtsc,
# int 2d, ptrace, /proc/self/status; prints addresses + suggested bypass per hit.
```

### 2. Windows: x64dbg + ScyllaHide profile
```text
# In x64dbg: Plugins → ScyllaHide → enable:
#   PEB BeingDebugged, NtGlobalFlag, HeapFlags, NtSetInformationThread(ThreadHideFromDebugger),
#   GetThreadContext(DR), KiUserExceptionDispatcher, NtClose, NtQuery*Information* spoofing,
#   timing (GetTickCount/rdtsc), OutputDebugString.
# For kernel-strength hiding load TitanHide.sys (test-signing / DSE off in the lab VM).
```

### 3. Linux: LD_PRELOAD ptrace neutralizer
```c
/* gcc -shared -fPIC -o noptrace.so noptrace.c ; LD_PRELOAD=./noptrace.so ./sample */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <sys/ptrace.h>
long ptrace(int req, ...) {            /* always succeed PTRACE_TRACEME, lie elsewhere */
    if (req == PTRACE_TRACEME) return 0;
    return 0;
}
```
Plus a `/proc/self/status` TracerPid filter via Frida (`scripts/frida_universal.js --hide-tracer`) or
a seccomp-free `open`/`read` LD_PRELOAD wrapper.

### 4. Frida-driven anti-anti-debug (cross-platform, from the universal script)
```javascript
// Windows: force IsDebuggerPresent → 0
const idp = Module.getExportByName('kernel32.dll', 'IsDebuggerPresent');
Interceptor.replace(idp, new NativeCallback(() => 0, 'int', []));
// Zero debug registers handed back by GetThreadContext
const gtc = Module.getExportByName('kernel32.dll', 'GetThreadContext');
Interceptor.attach(gtc, { onLeave() { /* walk CONTEXT, zero Dr0..Dr3 */ } });
// Linux: ptrace → 0  ; read() filter to scrub TracerPid
Interceptor.replace(Module.getExportByName(null,'ptrace'),
  new NativeCallback(()=>0,'long',['int','int','pointer','pointer']));
```

### 5. Runtime-packer OEP dump (UPX + generic)
```bash
# Known packer:
upx -d ./packed.exe -o ./unpacked.exe
# Generic runtime packer (Windows): run under x64dbg, set HW bp on the tail-jump to OEP
#   (look for: section-hop into a low-entropy region, sudden call into image base+entry).
#   At OEP → Scylla (x64dbg plugin): IAT autosearch → Get Imports → Dump → Fix Dump.
# Generic (Linux/ELF): break at unpacking stub end, dump the now-decrypted .text:
gdb -q ./packed -ex 'b *unpack_done' -ex run \
    -ex 'dump memory dumped.bin $base $base+0x40000' -ex quit
```

## Detection

```yaml
title: Anti-Debug API Cluster in Single Process (malware self-protection)
id: antidebug-cluster-0003
status: experimental
logsource: { category: api_monitoring }   # EDR userland telemetry
detection:
  apis:
    CalledApi|all:
      - 'NtSetInformationThread'           # ThreadHideFromDebugger
      - 'NtQueryInformationProcess'        # ProcessDebugPort/Flags
      - 'GetThreadContext'                 # DR read
  timing:
    CalledApi: 'rdtsc'                      # tight loops
  condition: apis and timing
level: high
tags: [attack.t1622, attack.t1497.001]
```
IOCs of an analyst bypassing: hooked Nt* prologues (jmp to shim), DR0-7 zeroed by GetThreadContext hook,
TitanHide driver loaded, ScyllaHide DLL injected into x64dbg/ida.

## OPSEC

- **Touches:** patches and hooks live in the *analysis VM* only. ScyllaHide injects a DLL into the
  debugger; TitanHide loads a kernel driver (needs test-signing / DSE off — never on a prod box).
- **Cleanup:** revert to the pre-run VM snapshot after each detonation; remove `LD_PRELOAD` shims;
  unload TitanHide. Dumped/unpacked binaries are analysis artifacts — do not redeploy.
- **Evasion (of the sample's checks):** classify before acting (API/flag/timing/exception/multi-process);
  apply ScyllaHide first, then patch residuals with Frida/binary patch, then verify the sample no longer
  early-exits. For multi-stage packers, dump iteratively (each layer reveals the next).

## References

- ScyllaHide anti-debug techniques — https://deepwiki.com/x64dbg/ScyllaHide/4-anti-debugging-techniques
- ScyllaHide / TitanHide — https://github.com/x64dbg/ScyllaHide ; https://github.com/mrexodia/TitanHide
- Defeating VMProtect's anti-debug (KiUserExceptionDispatcher, Heaven's Gate) — https://cyber.wtf/2023/02/09/defeating-vmprotects-latest-tricks/
- al-khaser (anti-debug/anti-VM test harness) — https://github.com/LordNoteworthy/al-khaser
- "Unmasking the Shadows" — pinpointing anti-dynamic-analysis with LLMs (2024) — https://arxiv.org/pdf/2411.05982
