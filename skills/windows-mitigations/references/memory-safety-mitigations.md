# Memory-Safety Exploit Mitigations: ASLR / DEP / CFG / XFG / CET / SEHOP

Cluster covering the userland mitigations that a memory-corruption exploit must defeat, and how
they compose on Windows 11 24H2. The realistic chain is: **info leak → defeat ASLR → build
ROP/JOP that survives CFG/XFG and CET → flip page executable (DEP) → execute**, or skip code
execution entirely with a **data-only** attack.

## Theory / Mechanism

| Mitigation | Protects | Mechanism | Enforced by |
|------------|----------|-----------|-------------|
| DEP/NX | data pages | NX bit: stack/heap pages non-executable, #PF on execute | CPU + PTE |
| ASLR | base addresses | Randomize image/stack/heap/PEB bases | loader |
| HEASLR | 64-bit images | High-entropy bottom-up randomization (~24 bits) | loader |
| CFG | forward edge | Bitmap of valid indirect-call targets; `_guard_check_icall` | compiler + ntdll |
| XFG | forward edge | CFG + per-prototype type hash stored above target; CET-backed | compiler + CET |
| CET shadow stack | backward edge | HW copy of return addresses; `RET` mismatch → #CP | CPU (Tiger Lake+) |
| CET IBT | forward edge | Indirect branch target must be `ENDBR64`; else #CP | CPU |
| SEHOP | SEH chain | Validates SEH chain terminates at known record | ntdll |

CET = Intel Control-flow Enforcement Technology. The shadow stack is the **backward-edge**
guarantee (return addresses, hardware-enforced — normal stores from any ring cannot write shadow
pages); IBT is the **forward-edge** guarantee (`ENDBR64` landing pads). XFG is Microsoft's
finer-grained CFG successor that relies on CET; it reduces valid transfer points ~100–1000x by
hashing the callee prototype, but the backward edge still hinges entirely on the CET shadow stack.

### Fingerprinting (do this first)
```c
// SetProcessMitigationPolicy / GetProcessMitigationPolicy enums of interest:
PROCESS_MITIGATION_DEP_POLICY                  dep;    // ProcessDEPPolicy
PROCESS_MITIGATION_ASLR_POLICY                 aslr;   // ProcessASLRPolicy (EnableHighEntropy, ForceRelocateImages)
PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY   cfg;    // ProcessControlFlowGuardPolicy
PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY    cet;    // ProcessUserShadowStackPolicy (EnableUserShadowStack, .._StrictMode, AuditUserShadowStack)
GetProcessMitigationPolicy(GetCurrentProcess(), ProcessUserShadowStackPolicy, &cet, sizeof cet);
```
PowerShell: `Get-ProcessMitigation -Name target.exe` (UserShadowStack = ON/OFF/AUDIT).
Per-image opt-in is recorded in the PE load-config (`GuardFlags`,
`IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT`). A module compiled without `/CETCOMPAT` does **not**
get shadow-stack enforcement; many third-party/legacy DLLs in a target process are not CET-compat.

## ASLR / HEASLR Defeat

1. **Information leak** — the universal primitive. A relative read (UAF, type confusion, OOB read)
   that discloses a code/heap pointer lets you compute a module base. Without a leak, none of the
   later steps are reliable on 64-bit. This is the single most important step.
2. **Partial overwrite** — the low 12 bits (page offset) are not randomized; overwrite only the
   low 1–2 bytes of a pointer to retarget within the same page/region without knowing the base.
3. **Non-ASLR module** — a DLL linked without `/DYNAMICBASE` loads at a fixed preferred base.
   `ForceRelocateImages` (Mandatory ASLR) can override this, but is off in many processes. Find
   them with `scripts/find_nonaslr_modules.py` (parses `IMAGE_DLLCHARACTERISTICS.DYNAMIC_BASE`).
4. **Predictable spray** — high-address heap spray for 32-bit; mostly dead on 64-bit HEASLR.

```bash
python scripts/find_nonaslr_modules.py "C:\Program Files\Target\*.dll"
# DLLs printed with DYNAMIC_BASE=False are fixed-base → ROP source even without a leak
```

## DEP/NX Bypass

DEP forces shellcode out of writable pages. Two routes:

- **ROP → make memory executable.** Chain gadgets to call `VirtualProtect(addr, size,
  PAGE_EXECUTE_READWRITE, &old)` (or `VirtualAlloc` / `NtProtectVirtualMemory`), then jump to your
  now-executable buffer. This is the classic and still the default.
- **ret2libc / direct API.** Call an existing API that does what you need without ever placing
  shellcode (e.g., `WinExec`, `system`).

```python
# pwntools-style ROP to flip the shellcode buffer to RWX then execute it (x64)
from pwn import *
context.arch = 'amd64'
rop = ROP(elf)                         # elf = leaked-base module
rop.raw(rop.find_gadget(['ret']).address)   # stack-align before the API call
rop.call(elf.symbols['VirtualProtect'],
         [shellcode_addr, 0x1000, 0x40, writable_scratch])  # 0x40 = PAGE_EXECUTE_READWRITE
rop.call(shellcode_addr)               # jump into newly-executable buffer
payload = b'A'*offset + rop.chain()
```

## CFG / XFG Bypass

CFG validates only the **target**, never the **call site** — it is coarse-grained. Bypasses:

1. **Valid-target dispatch gadget.** Overwrite an indirect-call pointer (e.g., a C++ vtable entry)
   with another *valid* CFG target that gives you control: `longjmp`, coroutine resume, a virtual
   destructor, or the loader's `__guard_dispatch_icall_fptr` itself. Because the target is in the
   bitmap, CFG allows the call. `scripts/cfg_dispatch_gadget_finder.py` parses the Guard CF
   Function Table from the PE load-config and lists which gadget candidates are CFG-valid.
2. **Functions not covered by the bitmap.** Dynamically generated / JIT code and non-CFG modules
   have no bitmap coverage; an indirect call into them is unchecked.
3. **Bitmap corruption.** With an arbitrary write, clear bits in `ntdll!LdrSystemDllInitBlock`
   CFG bitmap region to mark your target valid (needs a strong write primitive).
4. **COOP** (Counterfeit Object-Oriented Programming) — chain whole virtual methods that are each
   legitimate CFG targets, using counterfeit objects to pass control between them.

**XFG note:** XFG adds a per-prototype type hash above each target and validates it, shrinking the
valid set drastically. A vtable-overwrite bypass now requires a *type-hash-compatible* call target
(same prototype hash), so dispatch gadgets must match the expected function signature. The
backward edge is unchanged — see CET below. (Source: OffSec "eXtended Flow Guard Under The
Microscope".)

```bash
python scripts/cfg_dispatch_gadget_finder.py target.dll --xfg
# lists Guard-CF-valid exports + flags those that are also plausible dispatch gadgets
```

## CET Shadow Stack / IBT Bypass

With CET on, you cannot simply overwrite a return address — the `RET` compares against the shadow
stack and raises #CP. Practical approaches:

1. **Target a non-CET process / module.** CET is per-process opt-in (`/CETCOMPAT`,
   `EnableUserShadowStack`). Pick a target where `UserShadowStack = OFF`, or pivot into a
   non-CET module's code where return-address overwrite still works. Most exploited targets in the
   wild are not CET-strict. (Check with `scripts/Get-ProcessMitigationMap.ps1`.)
2. **JOP — Jump-Oriented Programming.** Avoid `RET` entirely so the shadow stack is never checked.
   Use a dispatcher gadget that advances through a dispatch table:
   `dispatcher: mov rax,[rbx]; add rbx,8; jmp rax`. Each functional gadget ends in `jmp
   [dispatch_table]`. Under IBT every JOP landing site must still begin with `ENDBR64`, which
   sharply limits gadgets — but IBT is even less widely enforced than the shadow stack.
3. **Forward-edge only.** Combine an XFG/CFG-valid forward-edge takeover (dispatch gadget) with a
   data-only payload, never overwriting a return address — the shadow stack is simply never
   exercised.
4. **Exception-unwind abuse.** Legitimate SEH/C++ unwinding rewrites the shadow stack via
   `RtlUnwind`/`_CxxFrameHandler`; corrupting unwind data can let a controlled handler resume with
   a consistent shadow-stack state. (Kernel-mode shadow-stack details: Synacktiv SSTIC 2025.)
5. **Kernel write of shadow stack.** `WRSS` (write-to-shadow-stack) is ring-0 in normal configs;
   only relevant once you already have kernel R/W (see byovd-vbs-hvci.md).

## SEHOP

SEHOP walks the SEH chain at dispatch and requires it to end in a validation record; a corrupted
chain raises an error instead of dispatching the attacker handler. Bypass by faking a complete,
correctly-terminated chain (place a valid final record pointing at ntdll's
`FinalExceptionHandler`), or simply target a process/build with SEHOP off. Largely a 32-bit
concern today.

## Composed Chain (CFG + DEP + ASLR + CET all on)

```
1. Info leak (UAF/type confusion/OOB read)      -> module base, defeat ASLR
2. Forward-edge takeover via CFG/XFG-valid       -> control flow without RET overwrite
   dispatch gadget (no shadow-stack interaction)    (defeats CET backward edge)
3. Dispatch gadget calls VirtualProtect           -> flip buffer RWX (defeats DEP)
   (VirtualProtect is a valid CFG target)
4. Jump to buffer / run data-only payload         -> objective
```
A data-only variant skips step 3–4: corrupt application state (auth flag, command buffer, token
pointer) so no executable memory is ever needed — the most mitigation-agnostic option.

## Detection

Sysmon / EDR signals and a Sigma rule for the most common DEP-bypass tell (a remote thread or the
target itself flipping a region to RWX then executing it):

```yaml
title: ROP DEP Bypass - VirtualProtect to RWX Followed by Execution
id: 9c1f0e2a-7d4b-4f1a-9b2c-5e6f7a8b9c01
status: experimental
logsource:
  product: windows
  category: process_access        # Sysmon EID 10 / EDR API telemetry
detection:
  rwx_protect:
    CallTrace|contains: 'VirtualProtect'   # or NtProtectVirtualMemory
    # EDR-side: new protection includes PAGE_EXECUTE_READWRITE (0x40)
  selection_alloc:
    GrantedAccess|contains: '0x40'
  condition: rwx_protect and selection_alloc
fields: [SourceImage, TargetImage, CallTrace]
falsepositives: [JIT engines (.NET, V8, Java), legitimate packers]
level: medium
```
Concrete telemetry/IOCs: WER/crash dumps from failed attempts; CPU `#CP` (Control-Protection,
vector 21) and `#PF` events; EDR stack-walks on `VirtualProtect`/`VirtualAlloc`/
`NtProtectVirtualMemory` showing an unbacked (non-image) return address; CET audit-mode logs
(`Microsoft-Windows-Kernel-CETShadowStack` / mitigation-audit ETW). XFG/CFG violations surface as
`STATUS_STACK_BUFFER_OVERRUN` (0xC0000409, FAST_FAIL_GUARD_ICALL_CHECK_FAILURE).

## OPSEC

- ROP/JOP and `VirtualProtect→RWX` are heavily stack-walked by EDR. Prefer **data-only** attacks,
  or allocate RW then RX in two steps (avoid RWX), or reuse already-RX signed regions.
- Failed exploitation generates WER reports and crash dumps — an IOC and an artifact for IR. Tune
  reliability before firing; clean up `%LOCALAPPDATA%\CrashDumps` and WER queues if appropriate.
- CET/XFG audit mode is silent telemetry: even a "successful" non-CET path may be logged if the
  process runs in audit. Confirm enforcement vs audit during recon.
- Choosing a non-CET / non-CFG target is the lowest-noise option but is itself visible (you ran a
  weaker process); blend with normal usage of that process.

## References

- Offensive Security — *eXtended Flow Guard Under The Microscope* (XFG type-hash, vtable bypass): https://www.offsec.com/blog/extended-flow-guard/
- meekolab — *Control-Flow Enforcement on Windows With CFG and Intel CET*: https://research.meekolab.com/control-flow-enforcement-on-windows-with-cfg-and-intel-cet
- Synacktiv — *Analyzing the Windows kernel shadow stack mitigation* (SSTIC, 2025-06-05): https://www.synacktiv.com/sites/default/files/2025-06/sstic_windows_kernel_shadow_stack_mitigation.pdf
- Intel — *Complex Shadow-Stack Updates (CET)*: https://www.intel.com/content/www/us/en/content-details/785687/
- Microsoft Learn — *Kernel-mode Hardware-enforced Stack Protection*: https://learn.microsoft.com/en-us/windows-server/security/kernel-mode-hardware-stack-protection
