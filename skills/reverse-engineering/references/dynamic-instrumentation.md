# Dynamic Instrumentation & Symbolic Execution

Cluster: observing and steering a binary at runtime — debuggers, function-level hooking, and
symbolic/concolic engines that reason about *all* inputs rather than one concrete run.
ATT&CK: T1622 (Debugger Evasion — the analyst's debugging is what target anti-RE fights),
T1480.001 (Execution Guardrails — symbolic execution recovers the guardrail/keying logic),
T1562.001 (Impair Defenses — when hooks disable SSL pinning / integrity checks). CWE: methodology.

## Theory / Mechanism

Three layers, increasing in power and cost:
1. **Debugging** (GDB/GEF, x64dbg, WinDbg) — concrete single-run inspection: breakpoints, memory/stack
   views, register edits. Best for "what does it do *here, now*."
2. **Dynamic Binary Instrumentation** (Frida/Gum, Pin, DynamoRIO) — inject JS/native into a live process,
   intercept any function, rewrite args/returns, and Stalk every executed block. Best for hooking many
   functions, on-device mobile, and modifying behavior without patching the file.
3. **Symbolic/Concolic execution** (angr, Triton, S2E) — represent inputs as symbolic variables, fork on
   branches, and ask an SMT solver (Z3) for inputs that reach a target / satisfy a constraint. Best for
   solving "what input unlocks path X" (license checks, crackmes, deobfuscation, magic constants).

## Modern 2024-2026 Reality (verified)

- **Frida 17.x** is the current line (e.g. `frida-server-17.5.1-android-*`). Apps now detect it via
  `/proc/self/maps` (`frida-agent.so`), default port **27042**, telltale threads `gum-js-loop`/`gmain`,
  and native string scans for `frida`/`gum`/`ptrace`. Counter with **gadget + `-l` script mode**, embed
  the gadget in the APK (self-contained agent), and stub `ptrace` via a `NativeCallback` returning -1.
- **Layered SSL unpinning** is now required: hook `okhttp3.CertificatePinner.check`,
  `javax.net.ssl.X509TrustManager.checkServerTrusted`, Conscrypt `TrustManagerImpl.checkServerTrusted`,
  and `CertificateChainCleaner.check` simultaneously (single-method scripts miss modern stacks).
  Fallbacks: `objection` (auto gadget inject), `medusa` (90+ modules), `apk-mitm` (static patch).
- **Triton backward slicing** is the 2024-2025 workhorse for deobfuscation: Google's LummaC2 writeup
  used Triton's backward-tracing API to separate obfuscator dispatcher instructions from original code
  by slicing the symbolic expressions feeding a register at a point. **`dAngr`** (BAR 2025) lifts
  debugging to a symbolic level on top of angr's VEX, cross-architecture.
- **angr** remains the broad framework (CLE loader, SimState plugins, CFGFast, VEX). Triton (C++ + Py
  bindings, integrates with Pin) is faster per-instruction and the basis for QSynthesis, TritonDSE,
  and the **Titan** VMProtect devirtualizer.

## Complete Working Instrumentation

### 1. GDB / GEF concrete debugging
```bash
gdb -q ./target
gef> b *main
gef> run
gef> vmmap                       # memory layout (ASLR slide, RWX regions)
gef> telescope $rsp 20           # annotated stack
gef> search-pattern "AAAA"       # find bytes in mapped memory
# Conditional breakpoint + auto-commands:
gef> break *0x401234 if $rdi == 0x41414141
gef> commands
>   x/s $rsi
>   continue
> end
# Defeat ptrace anti-debug from inside GDB:
gef> catch syscall ptrace
gef> commands
>   set $rax = 0
>   continue
> end
```

### 2. Frida 17 universal hooking (see scripts/frida_universal.js)
```bash
frida -U -f com.target.app -l scripts/frida_universal.js --no-pause      # spawn+attach (Android)
frida -p $(pgrep target) -l scripts/frida_universal.js                   # attach (Linux/Win)
frida-trace -U -i 'JNI_OnLoad' -i 'recv*' -p <pid>                       # quick native tracing
```
Core native interception pattern:
```javascript
const f = Module.getExportByName(null, 'strcmp');
Interceptor.attach(f, {
  onEnter(args) { this.a = args[0].readUtf8String(); this.b = args[1].readUtf8String();
                  console.log(`strcmp("${this.a}","${this.b}")`); },
  onLeave(retval) { retval.replace(ptr(0)); }   // force equality
});
// Stalker: trace every basic block of a thread (coverage / control-flow recovery)
Stalker.follow(Process.getCurrentThreadId(), {
  events: { call: true, ret: false, exec: false },
  onCallSummary(s) { console.log(JSON.stringify(s)); }
});
```

### 3. angr — reach a target / solve for input
```python
import angr, claripy, logging
logging.getLogger('angr').setLevel('ERROR')
proj = angr.Project('./target', auto_load_libs=False)
flag = claripy.BVS('flag', 8 * 32)               # 32 symbolic bytes
st = proj.factory.full_init_state(stdin=flag)
for b in flag.chop(8):                            # printable constraint
    st.solver.add(b >= 0x20, b <= 0x7e)
simgr = proj.factory.simulation_manager(st)
simgr.explore(find=lambda s: b"Correct" in s.posix.dumps(1),
              avoid=lambda s: b"Wrong"  in s.posix.dumps(1))
if simgr.found:
    print("input:", simgr.found[0].solver.eval(flag, cast_to=bytes))
```

### 4. Triton — concolic emulation + backward slice
```python
from triton import TritonContext, ARCH, Instruction, MemoryAccess, CPUSIZE
ctx = TritonContext(ARCH.X86_64)
ctx.setConcreteMemoryAreaValue(0x400000, open('code.bin','rb').read())
ctx.setConcreteRegisterValue(ctx.registers.rip, 0x401000)
# symbolize an input buffer at 0x600000
for i in range(16):
    ctx.symbolizeMemory(MemoryAccess(0x600000 + i, CPUSIZE.BYTE))
pc = 0x401000
while pc and pc < 0x401abc:
    op = ctx.getConcreteMemoryAreaValue(pc, 16)
    inst = Instruction(pc, op); ctx.processing(inst)
    pc = ctx.getConcreteRegisterValue(ctx.registers.rip)
# backward slice the symbolic expr that defines RAX at the end (which inputs influenced it):
ast = ctx.getRegisterAst(ctx.registers.rax)
print(ctx.getModel(ast == 0x539))   # solve RAX==1337 for the symbolized inputs
```
The repository's `scripts/deflatten_triton.py` applies this slicing to CFG-flattening recovery.

## Detection

```yaml
title: Frida / Dynamic Instrumentation on Mobile/Endpoint
id: dyn-frida-0002
status: experimental
logsource: { product: linux, category: process_creation }
detection:
  proc:
    Image|endswith: ['/frida-server', '/frida', '/objection', '/medusa']
  ports:                       # netflow / ss enrichment
    DestinationPort: 27042
  artifacts:                   # file/maps telemetry
    TargetFilename|contains: 'frida-agent'
  condition: proc or ports or artifacts
level: medium
tags: [attack.t1622, attack.t1562.001]
```
App-side RASP IOCs: `frida-agent.so` mapped, listening on 27042, threads `gum-js-loop`/`gmain`,
`ptrace(PTRACE_TRACEME)` self-attach failing, native strings `frida`/`gum`/`su`/`magisk`.

## OPSEC

- **Touches:** Frida injects a thread + mmaps the agent into the *target* process (loud to RASP). GDB
  ptraces the target (sets `TracerPid`). Symbolic execution is fully offline on the analyst box (silent).
- **Cleanup:** detach Frida (`Stalker.unfollow`, `%detach`) to remove injected callbacks; kill any
  spawned gadget; remove pushed `frida-server` from `/data/local/tmp` after a mobile run.
- **Evasion:** use gadget+script-mode and APK-embedded gadgets to avoid the 27042 port and process
  enumeration; hook `ptrace`/`/proc/self/status` reads; for hardened RASP prefer Zygisk+Shamiko or
  KernelSU. Frida-17 hooks of internal methods can crash on app updates — pin script to app version.

## References

- Frida (releases / 17.x) — https://github.com/frida/frida
- Android anti-instrumentation & SSL-pinning bypass — https://hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/android-anti-instrumentation-and-ssl-pinning-bypass.html
- Medusa framework — https://github.com/Ch0pin/medusa
- angr — https://github.com/angr/angr ; dAngr (BAR 2025) — https://www.ndss-symposium.org/wp-content/uploads/bar2025-final14.pdf
- Triton — https://github.com/JonathanSalwan/Triton
- LummaC2 backward-slicing deobfuscation (Google/Mandiant) — https://cloud.google.com/blog/topics/threat-intelligence/lummac2-obfuscation-through-indirect-control-flow
