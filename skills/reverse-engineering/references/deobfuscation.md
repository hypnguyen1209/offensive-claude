# Deobfuscation: Strings, OLLVM Flattening & VM-Protectors

Cluster: recovering original logic from obfuscated code — encrypted strings / API hashing, OLLVM
control-flow flattening, mixed-boolean-arithmetic (MBA), and full code virtualization (VMProtect 3.x,
Themida). ATT&CK: T1027 (Obfuscated Files or Information), T1027.007 (Dynamic API Resolution),
T1027.009 (Embedded Payloads / multi-layer), T1027.013 (Encrypted/Encoded File), T1140 (Deobfuscate/
Decode Files or Information — the analyst action). CWE: methodology.

## Theory / Mechanism

- **String / API-hash obfuscation:** strings are XOR/RC4/AES-encrypted (or built on the stack) and
  decrypted on first use; APIs are resolved by hashing export names and comparing to constants. Recover
  by **emulating** the decryptor/resolver over each call site rather than reimplementing the algorithm.
- **Control-flow flattening (OLLVM):** structured `if/loop` is replaced by `while(1){ switch(state){...}}`
  — a dispatcher reads a state variable and jumps to the matching block; each block sets the next state.
  De-flatten by identifying the dispatcher, enumerating state values, and tracing each block's *real*
  successor to rebuild the original CFG.
- **MBA:** arithmetic identities (`x+y == (x^y)+2*(x&y)`) bloat expressions; simplify with a
  pattern/oracle/synthesis simplifier.
- **Virtualization (VMProtect/Themida):** native code is translated to a bespoke bytecode run by an
  embedded interpreter (fetch-decode-execute dispatcher). Each protected binary has a unique handler
  table. Recover by lifting handlers to an IR (VTIL/LLVM), optimizing, and recompiling to x86.

## Modern 2024-2026 Reality (verified)

- **Symbolic backward slicing** is the de-flattening method of record: Google's **LummaC2** analysis
  used **Triton**'s backward-tracing API to separate the obfuscator's injected dispatcher instructions
  from the function's original instructions by slicing the symbolic expression feeding the state
  register at a point. This generalizes to OLLVM-style flattening.
- **VMProtect 3.x devirtualization:** **NoVmp** (static, VTIL-based, VMProtect x64 3.0-3.5; needs an
  *already-unpacked* binary, pass `-base`); **VMP3-Disasm** (Triton emulation of VMINIT → taint VM
  regs → lift handlers); **Titan** and JonathanSalwan's **VMProtect-devirtualization** (symbolic
  execution + LLVM on pure functions). Key triage: VMProtect can *pack only* (functions left native,
  trivially dumpable) vs *virtualize* specific functions — confirm which before investing in lifting.
- **Themida:** **GUARD** (ACM SAC 2025) is emulation-based generic API de-obfuscation + unpacking with a
  scattered-IAT (sIAT) reconstruction, validated against Themida and VMProtect; Themida v3.x stores
  argument-insensitive trampolines in the `.themida` section.
- **General strategy** (community consensus): lift VM bytecode to a *compiler IR* (LLVM/VTIL) so standard
  optimization passes strip MBA/junk/register-swapping, then re-emit clean x86. **SATURN** and **Triton/
  QSynthesis** anchor the academic side.

## Complete Working Deobfuscation

### 1. String / API-hash decryption via Unicorn emulation (this skill's script)
```bash
# Emulate the in-binary decrypt routine at every xref and recover plaintext:
python3 scripts/string_decrypt_emu.py ./sample --func 0x401500 --auto-xref -o out/strings.txt
# For a single blob:
python3 scripts/string_decrypt_emu.py ./sample --func 0x401500 \
    --arg-rdi 0x600000 --data-file enc_blob.bin -o out/one.txt
```
The script maps the binary, sets up a stack, writes the encrypted buffer to a scratch page, points the
first arg at it, runs the decrypt function under Unicorn, and reads back the now-plaintext buffer.

### 2. API-hash resolution (precompute the hash→name table)
```python
# Match a sample's hashing constants against exported names to label dynamic imports.
import pefile
def ror13_add(s):                       # classic ROR-13 additive (metasploit-style)
    h = 0
    for c in s.encode():
        h = ((h >> 13) | (h << (32-13))) & 0xffffffff
        h = (h + c) & 0xffffffff
    return h
names = {}
for dll in ('kernel32.dll','ntdll.dll','ws2_32.dll'):
    pe = pefile.PE(rf'C:\Windows\System32\{dll}')
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name: names[ror13_add(exp.name.decode())] = (dll, exp.name.decode())
# Now look up the constants the sample compares against → label the resolver's results.
print(names.get(0x726774c, 'unknown'))
```

### 3. OLLVM de-flattening with Triton backward slicing
```bash
python3 scripts/deflatten_triton.py ./sample --func 0x401abc -o out/deflat.dot
# Output: recovered CFG (graphviz) mapping real predecessor→successor edges, dispatcher elided.
# Render: dot -Tpng out/deflat.dot -o out/deflat.png
```
Mechanism implemented in the script: locate the dispatcher (block with max in-degree), enumerate the
state-variable values, concolically execute each "real" block to learn the next state it writes, and
emit edges between real blocks only.

### 4. MBA simplification
```python
# pip install z3-solver  — prove/derive a simpler equivalent for a small MBA expression
from z3 import BitVec, BitVecVal, simplify
x, y = BitVec('x', 32), BitVec('y', 32)
mba = (x ^ y) + 2*(x & y)          # equals x + y
print(simplify(mba == x + y))      # → True  (verify the identity), then rewrite in the decompiler
# For automated recovery at scale use msynth / QSynthesis (oracle-guided synthesis).
```

### 5. VMProtect 3.x devirtualization workflow
```bash
# 0. If packed, dump first (Scylla at OEP) — NoVmp needs an unpacked PE + original image base.
# 1. Static devirtualize to VTIL → optimized x86:
NoVmp unpacked.exe -base 0x140000000
# 2. Alternative: emulate handlers with Triton (VMP3-Disasm) when static lifting stalls.
# 3. Themida API de-obfuscation: GUARD-style emulated trampoline resolution → rebuild IAT,
#    or trace the .themida trampolines in x64dbg and re-point IAT entries to real APIs.
```

## Detection

Deobfuscation is an *analyst* action performed offline (Unicorn/Triton emulate the sample; nothing runs
against a target). The detection-relevant counterpart is spotting the obfuscation/unpacking *as a
defender* watching a real host:

```yaml
title: On-Host String/Payload Decryption Burst (packed-malware unwrap)
id: deobf-runtime-0004
status: experimental
logsource: { category: api_monitoring }     # EDR userland + memory telemetry
detection:
  alloc:
    CalledApi: 'VirtualAlloc'
    Protection: 'PAGE_EXECUTE_READWRITE'      # RWX stage for unpacked code
  resolve:
    CalledApi|all: ['LdrLoadDll', 'LdrGetProcedureAddress']   # dynamic API resolution post-decrypt
  condition: alloc and resolve
level: medium
tags: [attack.t1027, attack.t1027.007, attack.t1620]
```
Static IOCs of obfuscated samples: high-entropy `.themida`/`.vmp0`/`.vmp1` sections, a tiny import
table with `LoadLibrary`/`GetProcAddress` only, flattened CFG (huge switch dispatcher), and MBA-bloated
arithmetic. YARA on section names + entropy gives cheap first-pass triage.

## OPSEC

- **Touches:** all techniques here run *offline* on the analyst box (Unicorn/Triton emulate; NoVmp is a
  static lifter). Emulation deliberately does **not** execute the sample's network/FS syscalls, so it is
  safe even for live malware — but stub or trap any `Interceptor`/syscall the decryptor makes so a clever
  sample cannot phone home through your emulator's hooks.
- **Cleanup:** recovered strings, deflattened CFGs, and devirtualized binaries are analysis artifacts in
  `out/`; treat devirtualized output as derived from the sample (same handling rules).
- **Evasion (of analysis traps):** virtualized samples sometimes detect emulation (instruction-count or
  unsupported-opcode probes) — when Triton/Unicorn diverges, fall back to a concrete run under x64dbg+
  TitanHide and dump post-decrypt. Confirm a devirtualized function against a concrete trace before
  trusting it; lifters (NoVmp) are explicitly PoC-grade and can mis-lift edge handlers.

## References

- NoVmp (VMProtect x64 3.x → VTIL) — https://github.com/can1357/NoVmp
- VMP3-Disasm (Triton handler lifting) — https://github.com/KiFilterFiberContext/VMP3-Disasm
- VMProtect-devirtualization (symbolic + LLVM) — https://github.com/JonathanSalwan/VMProtect-devirtualization
- LummaC2 indirect-control-flow deobfuscation (Triton backward slicing) — https://cloud.google.com/blog/topics/threat-intelligence/lummac2-obfuscation-through-indirect-control-flow
- GUARD: generic API de-obfuscation + unpacking (ACM SAC 2025) — https://dl.acm.org/doi/10.1145/3672608.3707893
- SATURN — LLVM-based deobfuscation framework — https://arxiv.org/pdf/1909.01752
- Triton / QSynthesis ecosystem — https://triton-library.github.io/