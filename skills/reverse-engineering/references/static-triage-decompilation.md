# Static Triage & Decompilation

Cluster: turning an unknown binary into readable, typed pseudo-code and a capability inventory.
ATT&CK: T1592.002 (Gather Victim Host Information: Software), T1518.001 (Security Software Discovery).
CWE: CWE-1395 (Dependency on Vulnerable Third-Party Component) for the dependency-ID outputs;
decompilation itself is a methodology, not a weakness class.

## Theory / Mechanism

Static triage answers four questions before a single instruction is read in depth: *what is it*
(format/arch/bitness/endianness), *how is it built* (mitigations, packer, compiler), *what can it do*
(imports, syscalls, capa-matched behaviors), and *where to look* (strings, entry points, large or
heavily-xref'd functions). Decompilation then lifts machine code to an intermediate representation
(Ghidra P-Code, Binary Ninja BNIL/HLIL, VEX) and reconstructs C-like source via data-flow analysis,
type propagation, and control-flow structuring. Recovery quality degrades with stripping, inlining
(LTO), PGO block reordering, and obfuscation — which is exactly where the 2025 AI-assisted layer adds
value: predicting names/types and repairing mis-recovered control flow.

## Modern 2024-2026 Reality (verified)

- **Ghidra 11.4.x** (11.4.2 built 2025-07-31; 11.4.3 built 2025-08-27) improved decompiler switch
  analysis (guard condition duplicated across blocks), fixed duplicated-boolean-expression inversion,
  added x86 **SSE4a** support, and requires/supports **Gradle 9**. The prior **11.3** (Feb 2025)
  shipped full-text search across all decompiled functions, a **JIT-accelerated P-Code emulator**, and
  first-class **PyGhidra** (CPython, not just Jython) — use PyGhidra for modern scripting.
- **Binary Ninja Sidekick** (commercial, agentic) recovers types/names/structures on stripped/obfuscated
  binaries, links every claim back to IL/asm/memory, and runs a background validation agent that catches
  type misrecovery and bad calling conventions; it is scriptable (Python) for headless pipelines.
- **MCP integrations** now bridge LLM clients to disassemblers: `GhidrAssistMCP` (Ghidra), Binary Ninja's
  MCP server (headless + multi-binary), and IDA MCP servers. This repo ships `ida-multi-mcp` and
  `jadx-mcp-server` MCP tools — drive IDA/JADX directly from the agent.
- **LLM4Decompile** research line: `LLM4Decompile-Ref` refines Ghidra pseudo-code; **SK²Decompile**
  (Oct 2025) is a two-phase "skeleton→skin" pipeline (structure recovery → identifier naming);
  **decompile-bench** (May 2025) gives 2M binary↔source pairs for eval. **`ReverserAI`** runs a local
  LLM (Apple-silicon-friendly) to suggest function names from Binary Ninja output offline.
- **Verification discipline (critical):** LLM decompilers hallucinate — never trust an AI-suggested
  type, name, or "vulnerability" without grounding it in IL/asm/xrefs. Treat AI output as a *hypothesis*
  and confirm by reading the decompiler graph and cross-references.

## Complete Working Triage + Decompilation

### 1. One-shot triage (this skill's script)
```bash
python3 scripts/triage.py ./sample -o out/triage.json
# Emits: format, arch/bits/endian, mitigations (NX/PIE/RELRO/Canary/CFG/Authenticode),
# Shannon entropy + packer guess, top strings, imports/exports, suspicious-API capability tags.
```

### 2. Manual triage primitives (exact commands)
```bash
file ./sample
rabin2 -I ./sample            # arch, bits, endian, lang, mitigations
rabin2 -zzz ./sample          # all strings incl. wide, with vaddr
rabin2 -i ./sample            # imports;  rabin2 -E ./sample  → exports
checksec --file=./sample      # NX RELRO Canary PIE FORTIFY (Linux)
# Windows PE mitigations / signature:
python3 -c "import pefile,sys; pe=pefile.PE(sys.argv[1]); print(hex(pe.OPTIONAL_HEADER.DllCharacteristics))" ./sample.exe
# DllCharacteristics bits: 0x40 DYNAMIC_BASE(ASLR) 0x100 NX 0x4000 CFG 0x0020 HIGH_ENTROPY_VA
# Capability detection (Mandiant capa) — maps code to ATT&CK + MBC:
capa ./sample -v
```

### 3. Ghidra 11.4 headless decompilation to C
```bash
export GHIDRA_HOME=/opt/ghidra_11.4.3_PUBLIC
"$GHIDRA_HOME/support/analyzeHeadless" /tmp/ghproj proj \
  -import ./sample -overwrite \
  -postScript DecompileToC.java -scriptPath ./scripts/ghidra
```
`DecompileToC.java` (drop in `scripts/ghidra/`, exports every function to a `.c`):
```java
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.io.*;
public class DecompileToC extends GhidraScript {
  public void run() throws Exception {
    DecompInterface dec = new DecompInterface();
    dec.openProgram(currentProgram);
    PrintWriter w = new PrintWriter(new FileWriter(currentProgram.getName()+".c"));
    for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
      DecompileResults r = dec.decompileFunction(f, 60, monitor);
      if (r.decompileCompleted()) w.println(r.getDecompiledFunction().getC());
    }
    w.close();
  }
}
```
Modern PyGhidra equivalent (CPython, Ghidra >=11.3):
```python
# pip install pyghidra ; needs GHIDRA_INSTALL_DIR set
import pyghidra
with pyghidra.open_program("./sample") as flat:
    prog = flat.getCurrentProgram()
    from ghidra.app.decompiler import DecompInterface
    dec = DecompInterface(); dec.openProgram(prog)
    fm = prog.getFunctionManager()
    for f in fm.getFunctions(True):
        res = dec.decompileFunction(f, 60, None)
        if res.decompileCompleted():
            print(res.getDecompiledFunction().getC())
```

### 4. radare2 / rizin fast triage
```bash
r2 -A ./sample
> aaa            # full analysis
> afl~vuln       # functions matching 'vuln'
> pdc @ main     # decompiled (r2dec/r2ghidra)  ;  pdg @ main with r2ghidra plugin
> axt @ sym.imp.system   # xrefs to system()
> /R pop rdi             # ROP gadget search
```

### 5. AI/MCP-assisted pass (this repo's MCP tools)
```text
# Drive IDA headlessly through the ida-multi-mcp server (already wired in this environment):
#   survey_binary  → high-level overview
#   decompile <ea> → pseudo-C   ;  rename / set_type to fix recovery
#   xrefs_to <ea>  → caller graph ;  trace_data_flow for taint
# For Android: jadx-mcp-server (get_class_source, get_method_by_name, search_classes_by_keyword).
# ALWAYS verify AI/MCP suggestions against disasm before recording a finding.
```

## Detection

```yaml
title: Reverse-Engineering Toolchain Execution (lab-monitoring / insider-RE detection)
id: re-triage-toolchain-0001
status: experimental
logsource: { product: windows, category: process_creation }
detection:
  selection:
    Image|endswith:
      - '\ghidraRun.bat'
      - '\analyzeHeadless.bat'
      - '\ida64.exe'
      - '\rizin.exe'
      - '\r2.exe'
  condition: selection
level: low
tags: [attack.t1592.002]
```
This cluster runs on the *analyst* host, so target-side detection is N/A. The Sigma above is for
catching unauthorized RE activity on a managed estate (insider / DLP). IOCs of *being analyzed*: none —
triage and decompilation never touch the target.

## OPSEC

- **Touches:** the analyst's filesystem only. Decompilation/triage do not execute the sample (capa and
  `pefile` parse statically). Keep samples in an isolated, snapshotted analysis VM with no network.
- **Cleanup:** Ghidra projects, `.c` exports, and capa output stay in `out/`; shred sample copies per
  ROE/evidence-handling rules. AI/MCP calls may send code snippets to a model — for sensitive samples
  use the *local* path (ReverserAI / Ollama-backed MCP), never a cloud LLM.
- **Evasion (of false conclusions):** the real risk is analytical, not detective — anchor every AI claim
  in IL/asm; mark unverified hypotheses as such in the finding record.

## References

- Ghidra 11.4.2/11.4.3 Change History — https://www.ghidradocs.com/11.4.3_PUBLIC/docs/ChangeHistory.html
- Ghidra 11.3 release (PyGhidra, JIT P-Code emulator) — https://www.helpnetsecurity.com/2025/02/07/ghidra-11-3-released-new-features-performance-improvements-bug-fixes/
- Binary Ninja Sidekick — https://sidekick.binary.ninja/
- GhidrAssistMCP overview — https://skywork.ai/skypage/en/ghidrassist-ai-reverse-engineering/1978995688214220800
- LLM4Decompile / SK²Decompile / decompile-bench — https://github.com/albertan017/LLM4Decompile
- ReverserAI (local LLM RE assist) — https://github.com/mrphrazer/reverser_ai
- Mandiant capa — https://github.com/mandiant/capa
