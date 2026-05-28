---
name: reverse-engineering
description: Binary analysis, disassembly, decompilation, firmware RE, protocol reverse engineering, anti-reversing bypass, malware unpacking
metadata:
  type: offensive
  phase: analysis
  tools: ida, ghidra, radare2, binary-ninja, gdb, frida, x64dbg, angr, z3, capstone, unicorn
kill_chain:
  phase: [weaponize, exploit]
  step: [2, 4]
  attck_tactics: [TA0042, TA0002]
depends_on: [recon-osint]
feeds_into: [exploit-development, malware-analysis]
inputs: [binary_samples, firmware_images]
outputs: [disassembly_report, vulnerability_details, protocol_specs]
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

## Advanced: Firmware Analysis (UEFI/BIOS)

### UEFI Extraction & Analysis
```bash
# Extract UEFI firmware
UEFIExtract firmware.bin  # Extracts all volumes, sections, files
# Or: uefi-firmware-parser -e firmware.bin

# Identify DXE drivers (most attack surface)
# DXE drivers run with full hardware access before OS loads
# Vulnerable DXE driver = persistent pre-OS implant

# Common UEFI vulnerability classes:
# - SMM (System Management Mode) callout → ring -2 code execution
# - DXE driver buffer overflow → persistent implant
# - Secure Boot bypass → load unsigned bootloader
# - Variable overflow (NVRAM) → code execution in PEI/DXE phase

# Analyze with Ghidra:
# Load as PE/TE binary, set base address from volume header
# Look for: EFI_BOOT_SERVICES, EFI_RUNTIME_SERVICES calls
# Focus on: SMI handlers (SW SMI dispatch), variable access
```

### Secure Boot Bypass Research
```bash
# Secure Boot chain: UEFI → shim → GRUB → kernel
# Attack points:
# 1. Vulnerable signed bootloader (BlackLotus technique)
#    - Find old signed bootloader with known vulnerability
#    - Not yet revoked in DBX (Secure Boot blacklist)
#    - Use it to load unsigned code

# 2. GRUB vulnerabilities (BootHole, CVE-2020-10713)
#    - Buffer overflow in GRUB config parsing
#    - Craft malicious grub.cfg → code execution before kernel

# 3. Shim vulnerabilities
#    - Bypass signature verification in shim loader
#    - Load arbitrary EFI binary

# Check revocation status:
# Parse DBX (Forbidden Signatures Database) from NVRAM
# Compare against known-vulnerable bootloader hashes
```

## Advanced: De-obfuscation Techniques

### Control Flow Flattening (OLLVM)
```python
# OLLVM flattens control flow into a switch-based dispatcher:
# Original: if/else/loops → Flattened: while(1) { switch(state) { ... } }
# 
# De-flattening approach:
# 1. Identify dispatcher (switch variable, state assignments)
# 2. Trace state transitions for each case
# 3. Reconstruct original control flow graph
# 4. Tools: D-810 (IDA plugin), SATURN, deflat.py

# Symbolic execution for de-obfuscation:
import angr

def deobfuscate_cfg(binary, func_addr):
    proj = angr.Project(binary, auto_load_libs=False)
    cfg = proj.analyses.CFGFast()
    func = cfg.functions[func_addr]
    
    # Identify dispatcher block (highest in-degree)
    dispatcher = max(func.blocks, key=lambda b: len(list(func.graph.predecessors(b))))
    
    # For each state value, trace execution to find real successor
    # Build de-obfuscated CFG from state transitions
```

### String Deobfuscation (Automated)
```python
# Common patterns:
# 1. XOR with key: for(i=0;i<len;i++) str[i] ^= key[i%keylen]
# 2. Stack strings: mov [rsp+0], 'H'; mov [rsp+1], 'e'; ...
# 3. RC4/AES encrypted strings decrypted at runtime
# 4. API hashing: hash(api_name) compared against constants

# Automated decryption with emulation:
from unicorn import *
from unicorn.x86_const import *

def emulate_decrypt(binary, func_addr, encrypted_data):
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    # Map code and data
    mu.mem_map(0x400000, 0x10000)
    mu.mem_write(0x400000, binary_code)
    # Map stack
    mu.mem_map(0x7f0000, 0x10000)
    mu.reg_write(UC_X86_REG_RSP, 0x7f8000)
    # Set up arguments (encrypted data pointer)
    mu.mem_map(0x600000, 0x1000)
    mu.mem_write(0x600000, encrypted_data)
    mu.reg_write(UC_X86_REG_RDI, 0x600000)
    # Emulate decryption function
    mu.emu_start(func_addr, func_addr + func_size)
    # Read decrypted result
    return mu.mem_read(0x600000, len(encrypted_data))

# IDAPython batch decryption:
# Find all xrefs to decrypt function → emulate each → add comments
```

### VM-Based Obfuscation (Themida/VMProtect)
```
# VM protectors convert native code to custom bytecode
# Custom interpreter executes bytecode at runtime
# Each protected binary has UNIQUE instruction set

# Analysis approach:
# 1. Identify VM entry point (push regs, setup VM context)
# 2. Identify VM dispatcher (fetch-decode-execute loop)
# 3. Map virtual opcodes to operations:
#    - Trace handler addresses for each opcode
#    - Classify: arithmetic, memory, control flow, stack
# 4. Build lifter: VM bytecode → intermediate representation
# 5. Optimize IR → recover original logic

# Tools:
# - VMP analysis: NoVmp, VMPAttack
# - Themida: Oreans UnVirtualizer
# - Generic: Triton (symbolic execution on VM handlers)
# - Manual: trace with x64dbg, log handler dispatches
```

## Advanced: Binary Diffing for 1-Day Development

### Systematic Patch Analysis
```bash
# 1. Obtain pre-patch and post-patch binaries
# Windows: download from Microsoft Update Catalog
# Linux: apt/yum cache or snapshot.debian.org

# 2. Generate function-level diff
# BinDiff: Export BinExport from IDA → BinDiff GUI
# Diaphora: IDA plugin, generates SQLite DB for comparison

# 3. Focus on changed functions:
# - Small changes (1-5 basic blocks modified) → likely the fix
# - Added bounds checks → buffer overflow
# - Added NULL checks → null deref / UAF
# - Changed comparison → logic bug / auth bypass
# - Added lock/mutex → race condition

# 4. Root cause analysis:
# What was the vulnerable code doing?
# What input reaches this code?
# What's the minimum trigger condition?

# 5. Exploit development:
# Craft input that triggers the pre-patch vulnerable path
# Verify on unpatched version
# Assess: is it reachable remotely? What privileges needed?
```

### Windows Patch Tuesday Analysis
```bash
# Monthly workflow:
# 1. Download advisory details (MSRC)
# 2. Identify interesting CVEs (RCE, EoP in common components)
# 3. Download patched DLL/SYS from Update Catalog
# 4. Get pre-patch version from previous month's update
# 5. BinDiff the specific component
# 6. Focus on: win32k.sys, ntoskrnl.exe, HTTP.sys, Exchange, RPC runtime

# Automation:
# winbindex.m417z.com — index of Windows binaries by version
# Download specific versions of any Windows DLL
```

## Advanced: Protocol Reverse Engineering

### Network Protocol RE
```python
# Methodology:
# 1. Capture traffic (Wireshark/tcpdump)
# 2. Identify message boundaries (length prefix, delimiter, fixed size)
# 3. Classify message types (request/response, different commands)
# 4. Map fields: header, type, length, payload, checksum
# 5. Identify encoding: raw binary, protobuf, msgpack, custom

# Wireshark dissector (Lua) for custom protocol:
local proto = Proto("custom", "Custom Protocol")
local f_type = ProtoField.uint8("custom.type", "Message Type")
local f_len = ProtoField.uint16("custom.len", "Payload Length")
local f_data = ProtoField.bytes("custom.data", "Payload")
proto.fields = {f_type, f_len, f_data}

function proto.dissector(buffer, pinfo, tree)
    local subtree = tree:add(proto, buffer())
    subtree:add(f_type, buffer(0,1))
    subtree:add(f_len, buffer(1,2))
    local payload_len = buffer(1,2):uint()
    subtree:add(f_data, buffer(3, payload_len))
end

local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(4444, proto)
```

### Proprietary File Format RE
```python
# Approach:
# 1. Collect multiple samples of the format
# 2. Hex diff samples → identify fixed vs variable regions
# 3. Identify magic bytes (file signature)
# 4. Map structure: header → sections → data
# 5. Cross-reference with binary that parses the format

# 010 Editor template / Kaitai Struct for documentation:
# Define format as structured grammar
# Enables automated parsing and fuzzing

# Fuzzing the parser:
# Once format is understood → mutate valid files
# Target: length fields (overflow), count fields (OOB), offsets (arbitrary read)
```
