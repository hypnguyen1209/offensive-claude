---
name: reverse-engineering
description: Binary analysis, disassembly, decompilation, firmware RE, protocol reverse engineering, anti-reversing bypass, malware unpacking
metadata:
  type: offensive
  phase: analysis
  tools: ida, ghidra, radare2, binary-ninja, gdb, frida, x64dbg, angr, z3, capstone, unicorn
---

# Reverse Engineering

## When to Activate

- Analyzing compiled binaries for vulnerabilities
- Understanding proprietary protocols or file formats
- Malware analysis and unpacking
- Firmware extraction and analysis
- Bypassing anti-debugging/anti-tampering protections
- CTF binary challenges
- Patch diffing to find 1-day vulnerabilities

## Static Analysis

### Initial Triage
```bash
# File identification
file target_binary
rabin2 -I target_binary  # binary info (arch, bits, endian, protections)

# Strings extraction
strings -n 8 target_binary | grep -iE '(password|key|secret|flag|http|/bin)'
rabin2 -z target_binary   # strings with addresses
rabin2 -zz target_binary  # all strings including wide

# Imports/Exports
rabin2 -i target_binary   # imports
rabin2 -E target_binary   # exports
objdump -T target_binary  # dynamic symbols

# Security mitigations
checksec --file=target_binary
# RELRO, Stack Canary, NX, PIE, FORTIFY
```

### Disassembly & Decompilation
```bash
# Ghidra headless analysis
analyzeHeadless /tmp/ghidra_project proj -import target_binary \
  -postScript ExportDecompilation.java -scriptPath /scripts/

# radare2 analysis
r2 -A target_binary
> afl          # list functions
> axt @sym.target_func  # xrefs to function
> pdf @main    # disassemble function
> VV @main     # visual graph mode
> afn new_name @addr  # rename function

# IDA (via MCP or IDAPython)
# Decompile function, rename variables, set types
# Cross-references: xrefs_to(addr), xrefs_from(addr)
```

### Pattern Recognition
```
# Common vulnerability patterns in disassembly:
# - strcpy/sprintf without bounds → buffer overflow
# - malloc(user_controlled_size) → integer overflow
# - free() followed by use → UAF
# - system()/exec() with user data → command injection
# - Custom crypto (XOR loops, fixed keys) → weak encryption
```

## Dynamic Analysis

### Debugging
```bash
# GDB with pwndbg/GEF
gdb -q ./target
> break *main
> run
> vmmap              # memory layout
> heap              # heap state
> telescope $rsp 20 # stack inspection
> search-pattern "AAAA"  # find pattern in memory

# Conditional breakpoints
> break *0x401234 if $rax == 0x41414141
> commands
>   x/s $rdi
>   continue
> end

# Anti-debug bypass
> catch syscall ptrace
> commands
>   set $rax = 0
>   continue
> end
```

### Frida Instrumentation
```javascript
// Hook function and modify behavior
Interceptor.attach(Module.findExportByName(null, "strcmp"), {
    onEnter: function(args) {
        console.log("strcmp(" + args[0].readUtf8String() + ", " + args[1].readUtf8String() + ")");
    },
    onLeave: function(retval) {
        retval.replace(0); // force match
    }
});

// Bypass SSL pinning (Android)
Java.perform(function() {
    var TrustManager = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManager.verifyChain.implementation = function() {
        return arguments[0];
    };
});

// Trace all JNI calls
Java.perform(function() {
    var System = Java.use('java.lang.System');
    System.loadLibrary.implementation = function(lib) {
        console.log("Loading: " + lib);
        this.loadLibrary(lib);
    };
});
```

### Symbolic Execution
```python
import angr, claripy

proj = angr.Project('./target', auto_load_libs=False)
state = proj.factory.entry_state()

# Symbolic input
sym_input = claripy.BVS('input', 8 * 32)
state.memory.store(input_addr, sym_input)

# Explore to find path to target
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=target_addr, avoid=avoid_addrs)

if simgr.found:
    solution = simgr.found[0].solver.eval(sym_input, cast_to=bytes)
    print(f"Input: {solution}")
```

## Firmware Analysis

```bash
# Extraction
binwalk -e firmware.bin
# Filesystem extraction
binwalk --dd='.*' firmware.bin
unsquashfs squashfs-root.img

# Identify architecture
file extracted_binary
readelf -h extracted_binary

# Emulation
qemu-system-arm -M versatilepb -kernel zImage -dtb vexpress.dtb -drive file=rootfs.img

# Common targets in firmware:
# - /etc/shadow, /etc/passwd (hardcoded creds)
# - Web server configs (lighttpd, uhttpd)
# - init scripts (startup services)
# - Proprietary binaries (custom protocols)
# - Certificate/key files
```

## Anti-Reversing Bypass

| Technique | Bypass |
|-----------|--------|
| IsDebuggerPresent | Patch return value, hook API |
| ptrace(PTRACE_TRACEME) | LD_PRELOAD hook, patch syscall |
| Timing checks (rdtsc) | Patch comparison, single-step with HW breakpoints |
| Self-modifying code | Dump after unpacking, trace execution |
| VM detection | Patch CPUID, hide VM artifacts |
| Obfuscation (OLLVM) | Symbolic execution, pattern matching, devirtualization |
| Packed binaries | Run until OEP, dump from memory |
| Anti-disassembly | Fix control flow, NOP junk bytes |

## Patch Diffing (1-day Research)

```bash
# BinDiff / Diaphora workflow:
# 1. Get vulnerable version and patched version
# 2. Generate IDB/BinExport for both
# 3. Diff — focus on changed functions
# 4. Analyze what was fixed → understand the vulnerability
# 5. Write exploit for the pre-patch version

# Key indicators in patches:
# - Added bounds checks → buffer overflow
# - Added NULL checks → null deref / UAF
# - Changed comparison logic → auth bypass
# - Added sanitization → injection
# - Changed allocation size → heap overflow
```
