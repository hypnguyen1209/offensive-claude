---
name: windows-mitigations-bypass
description: Use when bypassing a Windows exploit/platform mitigation — ASLR/DEP/CFG/XFG/CET, ACG/CIG, WDAC/App Control, ASR/AMSI/ETW, PPL/LSA Protection, BYOVD/VBS/HVCI
metadata:
  type: offensive
  phase: exploitation
  tools: [WinDbg, IDA, x64dbg, Process Hacker, ROPgadget, mona.py, PPLmedic, nanodump, EDRSandblast]
  mitre: [T1211, T1218, T1562.001, T1562.004, T1562.006, T1003.001, T1068, T1620, T1140]
kill_chain:
  phase: [exploit, installation]
  step: [4, 5]
  attck_tactics: [TA0002, TA0004, TA0005]
  attck_techniques: [T1211, T1218, T1562.001, T1562.004, T1562.006, T1003.001, T1068, T1620, T1112]
depends_on: [exploit-development, reverse-engineering]
feeds_into: [shellcode-dev, edr-evasion, windows-boundaries]
inputs: [mitigation_config, binary_analysis, target_os_build]
outputs: [bypass_technique, finding_record, mitigation_fingerprint]
references:
  - references/memory-safety-mitigations.md
  - references/acg-cig-dynamic-code.md
  - references/wdac-app-control-bypass.md
  - references/asr-amsi-etw-blinding.md
  - references/ppl-lsa-protection.md
  - references/byovd-vbs-hvci.md
scripts:
  - scripts/mitigation_recon.ps1
  - scripts/Get-ProcessMitigationMap.ps1
  - scripts/find_nonaslr_modules.py
  - scripts/cfg_dispatch_gadget_finder.py
  - scripts/extract_asr_exclusions.py
  - scripts/check_driver_blocklist.py
---

# Windows Mitigations & Bypass

Defeating both **exploit mitigations** (ASLR/DEP/CFG/XFG/CET/ACG) and **platform security controls**
(WDAC, ASR, AMSI/ETW, PPL/LSA Protection, VBS/HVCI). Every technique is paired with detection +
OPSEC so it doubles as defensive hardening guidance. Assumes an authorized engagement.

## When to Activate

- Fingerprinting a target's mitigation landscape before weaponizing an exploit
- Designing a memory-corruption exploit that must defeat ASLR + DEP + CFG/CET in one chain
- Bypassing application control (WDAC / App Control for Business) to run unsigned code
- Disabling or blinding telemetry (ASR, AMSI, ETW) ahead of post-exploitation
- Dumping a PPL/LSA-protected process (LSASS) or killing a PPL-protected EDR
- Deciding between userland-only vs BYOVD/kernel approaches based on VBS/HVCI state

## Technique Map

| Technique | ATT&CK | CWE | Reference | Script |
|-----------|--------|-----|-----------|--------|
| ASLR/HEASLR defeat (info leak, partial overwrite, non-ASLR module) | T1211 | CWE-330 | references/memory-safety-mitigations.md | scripts/find_nonaslr_modules.py |
| DEP/NX bypass (ROP→VirtualProtect, ret2libc) | T1211 | CWE-119 | references/memory-safety-mitigations.md | scripts/cfg_dispatch_gadget_finder.py |
| CFG/XFG bypass (valid-target dispatch gadget, type-hash collision) | T1211 | CWE-1240 | references/memory-safety-mitigations.md | scripts/cfg_dispatch_gadget_finder.py |
| CET shadow stack / IBT evasion (non-CET process, JOP, exception unwind) | T1211 | CWE-1419 | references/memory-safety-mitigations.md | scripts/Get-ProcessMitigationMap.ps1 |
| ACG/CIG bypass (signed-code reuse, JIT exemption, cross-process) | T1211, T1055 | CWE-94 | references/acg-cig-dynamic-code.md | scripts/Get-ProcessMitigationMap.ps1 |
| WDAC / App Control bypass (LOLBin, signed Electron/V8, sideload) | T1218 | CWE-693 | references/wdac-app-control-bypass.md | scripts/mitigation_recon.ps1 |
| ASR rule bypass (excluded path/process hollow, COM, syscalls) | T1562.001 | CWE-693 | references/asr-amsi-etw-blinding.md | scripts/extract_asr_exclusions.py |
| AMSI bypass (amsiInitFailed, AmsiScanBuffer patch, hardware bp) | T1562.001 | CWE-693 | references/asr-amsi-etw-blinding.md | scripts/mitigation_recon.ps1 |
| ETW blinding (EtwEventWrite patch, provider disable, NtTraceControl) | T1562.006 | CWE-778 | references/asr-amsi-etw-blinding.md | scripts/mitigation_recon.ps1 |
| PPL / LSA Protection bypass (PPLmedic userland chain, BYOVD) | T1003.001, T1562.001 | CWE-269 | references/ppl-lsa-protection.md | scripts/Get-ProcessMitigationMap.ps1 |
| BYOVD kernel R/W (unblocked driver, EPROCESS.Protection wipe) | T1068, T1562.001 | CWE-822 | references/byovd-vbs-hvci.md | scripts/check_driver_blocklist.py |
| VBS/HVCI/Credential Guard evasion (blocklist evasion, data-only) | T1068, T1562.001 | CWE-693 | references/byovd-vbs-hvci.md | scripts/check_driver_blocklist.py |

## Quick Start

```powershell
# 1. Fingerprint system + per-process mitigations, AMSI/ETW/ASR/WDAC/VBS state
powershell -ep bypass -f scripts/mitigation_recon.ps1 -OutJson recon.json
powershell -ep bypass -f scripts/Get-ProcessMitigationMap.ps1   # rank weak processes

# 2. If memory-corruption target: locate non-ASLR modules + CFG-valid dispatch gadgets
python scripts/find_nonaslr_modules.py C:\Target\*.dll
python scripts/cfg_dispatch_gadget_finder.py target.dll        # ROP/JOP under CFG/CET

# 3. If application control (WDAC) blocks execution: pick a signed bypass vessel
#    MSBuild inline C#, signed legacy Teams (Electron), or signed Node .node module

# 4. Blind telemetry before post-ex (use sparingly — patching is itself an IOC)
#    AMSI: patch AmsiScanBuffer / amsiInitFailed   ETW: patch EtwEventWrite

# 5. Credential access vs PPL/LSA: userland PPLmedic chain (no driver) or BYOVD
python scripts/extract_asr_exclusions.py                         # find ASR-excluded paths
python scripts/check_driver_blocklist.py mydriver.sys           # is driver blocklisted/HVCI-safe?
```

## OPSEC & Detection (summary)

| Technique | Telemetry / IOC | Detection (Sigma / EDR) | OPSEC note |
|-----------|-----------------|--------------------------|------------|
| ROP/JOP exploit | crash dumps, WER, #CP/#PF exceptions, RWX alloc | EDR stack-walk on VirtualProtect/VirtualAlloc; CFG/CET #CP telemetry | prefer data-only; reuse signed gadgets; avoid RWX |
| WDAC LOLBin | 4688 w/ MSBuild/mshta parent, child of office/explorer | Sigma proc_creation_win_lolbin_*; CodeIntegrity 3076/3077 audit | use Microsoft-signed Electron/V8 — looks like normal app |
| AMSI patch | RWX in amsi.dll, AMSI scan gaps | AMSI bypass detections, mem scan of amsi.dll .text | indirect syscalls; restore bytes; HWBP avoids byte edits |
| ETW patch | EtwEventWrite first byte = 0xC3/0xCC | ETW-TI sensor; integrity scan of ntdll EtwEventWrite | restore after use; or disable provider not whole API |
| PPL LSASS dump | handle to lsass w/ VM_READ, MiniDump call, 4656/4663 | Sysmon 10 GrantedAccess 0x1010/0x1410; Defender ASR 9e6c... | userland PPLmedic avoids driver IOC; rename per ASR excl. |
| BYOVD | Sysmon 6 driver load, svc create reg, unsigned-by-MS driver | Sysmon EID6 + reg EID13; MDE LOLDrivers hash hunt; blocklist | pick driver NOT in MS blocklist/LOLDrivers; HVCI may still block |
| VBS/HVCI off | bcdedit hypervisorlaunchtype off, DeviceGuard reg writes | reg EID13 on DeviceGuard; boot config change events | requires admin+reboot — loud; data-only attack instead |

## Deep Dives

- **references/memory-safety-mitigations.md** — ASLR/HEASLR, DEP/NX, CFG/XFG, Intel CET shadow stack + IBT, SEHOP: how each works on Win11 24H2 and concrete bypass chains (info leak → dispatch gadget → VirtualProtect).
- **references/acg-cig-dynamic-code.md** — Arbitrary Code Guard, Code Integrity Guard, Dynamic Code policy: signed-code-only reuse, JIT/browser exemptions, cross-process pivots, SEC_IMAGE section abuse.
- **references/wdac-app-control-bypass.md** — WDAC / App Control for Business: recommended-block-rule LOLBins, signed Electron (Loki C2) + signed Node `.node`/V8 exploitation, DLL sideloading, allow-list reality check.
- **references/asr-amsi-etw-blinding.md** — ASR rule bypasses (global exclusion abuse, process hollowing into trusted images), AMSI bypass variants, ETW blinding (full patch vs selective provider disable).
- **references/ppl-lsa-protection.md** — PPL levels & LSA Protection (RunAsPPL), userland PPLmedic exploit chain, PPLBlade/nanodump dumping, Credential Guard reality, BYOVD PPL kill.
- **references/byovd-vbs-hvci.md** — BYOVD kernel R/W primitive build, Microsoft driver blocklist + LOLDrivers + HVCI/Secure Boot evasion (Silver Fox amsdk.sys case), VBS/Credential Guard limits, kernel shadow stack.
