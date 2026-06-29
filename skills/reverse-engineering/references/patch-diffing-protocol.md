# Patch Diffing (n-day) & Protocol / File-Format RE

Two related n-day/analysis clusters. (a) **Patch diffing:** compare pre- and post-patch binaries to
recover a vulnerability's root cause and build a trigger before/around public PoC. (b) **Protocol &
file-format RE:** infer the structure of an unknown wire protocol or file format to parse, fuzz, or
exploit it. ATT&CK: T1203 (Exploitation for Client Execution — the n-day you build), T1592.002 (Gather
Software Information). CWE: depends on the recovered bug (the diff *tells you* the CWE).

## Theory / Mechanism

- **Patch diffing:** a security fix is usually a small, localized change (added bounds/NULL check,
  tightened comparison, new lock). Function-level binary diffing surfaces exactly which functions
  changed; the analyst then root-causes the *pre*-patch behavior and crafts the input that reaches it.
  Silent (undisclosed) fixes are found the same way.
- **Protocol/format RE:** without source, recover message boundaries (length-prefix / delimiter / fixed),
  classify message types, map fields (type/length/payload/checksum), and infer the state machine. Two
  paradigms: **NetT** (statistical inference over captured traffic) and **ExeT** (trace the binary that
  parses the protocol — more robust, gives semantics). Encode the recovered grammar in Kaitai/dissector
  for parsing and fuzzing.

## Modern 2024-2026 Reality (verified)

- **winbindex** (m417z) is the canonical way to fetch any Windows binary by KB/version/hash — no VM farm
  needed. Updates are cumulative (a single KB can touch 28k+ files), so pull the MSU/CAB, extract, and
  diff *only* the changed binaries.
- **Diffing engines:** **BinDiff** v8+ (free, needs BinExport from IDA/Ghidra) is fast on symbolized
  binaries but stumbles on PGO block reorder / LTO inlining / register-allocation churn; **Diaphora**
  (open source) adds fuzzy + graph-isomorphism matching and handles stripped binaries; **ghidriff**
  (clearbluejar) is a CLI Ghidra-based differ used by automation.
- **LLM-assisted triage (2025-2026):** **PatchWatch** (Origin, Rust) ingests an MSRC release, ranks CVEs
  (CVSS≥9.0 or actively-exploited → Tier-1), fetches winbindex pre/post binaries, runs ghidriff, and
  produces LLM-ready diff reports; **DiffRays** (pwnfuzz) does `diffrays autodiff --cve CVE-2025-29824`;
  SySS's **diffalyze** focuses on kernel drivers (used on `mrxsmb.sys` → CVE-2025-32718). **Caveat:**
  LLMs reliably summarize *memory* fixes but hallucinate new "vulns" and false-positive — reasoning
  models (o3/GPT-5-Thinking/Opus) do best; the *exploitability judgment stays human*. (PatchWatch itself
  publicly mis-attributed a CVE due to pulling the wrong pre-patch version — verify the binary version.)
- **Late-2025 high-value diff targets:** `cldflt.sys` (Cloud Files mini-filter UAF, CVE-2025-62221, a
  recurring driver in tutorials), Win32k (CVE-2025-62458), CLFS (`clfs.sys`, CVE-2025-62470 / earlier
  CVE-2025-1246), plus the perennial `afd.sys`, `ntoskrnl.exe`, `http.sys`. 2025 totaled 1,139 MS CVEs.
- **Protocol RE tooling:** **Netzob** (semi-auto inference: clustering → field partitioning → PFSM via
  extended Needleman-Wunsch alignment); **Kaitai Struct** (declarative `.ksy` → parsers in 8 langs +
  diagrams); research **BinPRE** (2024, ExeT field inference) and binary-protocol state-machine inference
  (arXiv Dec 2024). Hex/analysis aids: ImHex, 010 Editor, Synalysis, CyberChef.

## Complete Working n-day + Protocol RE

### 1. Fetch pre/post-patch Windows binary (this skill's script)
```bash
python3 scripts/patchdiff_fetch.py --pe afd.sys --kb-after KB5050000 -o out/diff/
# Queries winbindex for afd.sys, downloads the version shipped in KB5050000 and the prior version,
# writes out/diff/afd.sys.before and out/diff/afd.sys.after ready for BinDiff/Diaphora/ghidriff.
```
Manual MSU/CAB extraction (when diffing a whole update):
```bash
expand -F:* Windows10.0-KBxxxxxxx-x64.msu C:\out          # extract MSU → PSF/CAB
expand -F:* C:\out\Windows10.0-KBxxxxxxx-x64.cab C:\out\f # extract CAB → files
# diff only files that changed vs the prior cumulative.
```

### 2. Function-level diffing
```bash
# ghidriff (open source, scriptable):
ghidriff out/diff/afd.sys.before out/diff/afd.sys.after --engine VersionTrackingDiff -o out/diff/report
# BinDiff: generate BinExport from each (IDA: edit→plugins→BinExport / Ghidra extension), then:
bindiff --primary before.BinExport --secondary after.BinExport --output_dir out/diff/
# Diaphora: load before.idb, export DB; load after.idb, diff against it (best-match + partial lists).
# Triage order: smallest changed functions first; an added CMP/bounds check ⇒ overflow; added NULL
# check ⇒ UAF/null-deref; tightened comparison ⇒ auth/logic bug; new lock ⇒ race.
```

### 3. Network protocol inference (this skill's script)
```bash
python3 scripts/proto_infer.py capture.pcap --port 4444 -o out/proto/
# Splits messages by direction, finds candidate length fields (offset whose value tracks frame size),
# clusters messages, flags constant vs variable byte positions, and emits:
#   out/proto/fields.json, out/proto/custom.ksy (Kaitai), out/proto/custom.lua (Wireshark dissector).
```

### 4. Kaitai spec → multi-language parser (encode the recovered format)
```yaml
# custom.ksy — describe once, compile to C++/Py/Java/JS/... and a diagram
meta: { id: custom_proto, endian: be }
seq:
  - id: msg_type
    type: u1
  - id: length
    type: u2
  - id: payload
    size: length
```
```bash
kaitai-struct-compiler -t python --outdir out/proto custom.ksy     # → custom_proto.py parser
# Fuzz the recovered format with boofuzz/AFL++ targeting length/count/offset fields.
```

### 5. Wireshark dissector for live decoding
```lua
-- custom.lua (auto-emitted by proto_infer.py); place in Wireshark plugins dir
local proto = Proto("custom","Custom Protocol")
local f_type = ProtoField.uint8 ("custom.type","Type")
local f_len  = ProtoField.uint16("custom.len","Length")
local f_data = ProtoField.bytes ("custom.data","Payload")
proto.fields = { f_type, f_len, f_data }
function proto.dissector(buf, pinfo, tree)
  local t = tree:add(proto, buf())
  t:add(f_type, buf(0,1)); t:add(f_len, buf(1,2))
  t:add(f_data, buf(3, buf(1,2):uint()))
end
DissectorTable.get("tcp.port"):add(4444, proto)
```

## Detection

```yaml
title: Malformed/Replayed Custom-Protocol Frames (active protocol RE / n-day trigger)
id: proto-nday-0006
status: experimental
logsource: { product: ids, category: network }
detection:
  selection:
    dst_port: 4444
    payload_anomaly:                # length field disagreeing with actual frame size, or fuzz markers
      - 'length_mismatch'
      - 'high_entropy_burst'
  condition: selection
level: medium
tags: [attack.t1203, attack.t1592.002]
```
Patch diffing itself is invisible to the target (it pulls *public* binaries). Active protocol probing /
n-day triggering against a live service shows up as malformed frames, length-field mismatches, replayed
sequences, and crash-then-reconnect patterns in IDS / service logs.

## OPSEC

- **Touches:** patch diffing is fully offline against public Microsoft/distro binaries (zero target
  telemetry). Protocol RE from a *pcap* is passive; *active* probing/fuzzing hits the live service and
  can crash it.
- **Cleanup:** keep n-day PoCs in the lab until ROE/disclosure allows; never fire an unproven trigger at
  a production service you cannot recover. Pin the exact binary versions you diffed (avoid the PatchWatch
  wrong-version pitfall) and record KB/hash in the finding.
- **Evasion:** prefer passive capture over active probing when a live target is in scope; throttle and
  fence fuzzing to a non-prod replica; treat LLM diff summaries as leads, not findings — confirm the
  vulnerable path in the disassembler before writing the trigger.

## References

- winbindex — https://winbindex.m417z.com ; "Extracting and Diffing Windows Patches" (wumb0) workflow.
- Patch-diffing pipeline for n-day generation (Origin) — https://www.originhq.com/research/patch-diffing-pipeline ; PatchWatch — https://github.com/originsec/patchwatch
- DiffRays — https://github.com/pwnfuzz/diffrays ; SySS automated patch-diff with LLMs — https://blog.syss.com/posts/automated-patch-diff-analysis-using-llms/
- ghidriff — https://github.com/clearbluejar/ghidriff ; Diaphora — https://github.com/joxeankoret/diaphora ; BinDiff — https://github.com/google/bindiff
- Netzob — https://github.com/netzob/netzob ; Kaitai Struct — https://kaitai.io ; BinPRE field inference (2024) — https://arxiv.org/pdf/2409.01994
