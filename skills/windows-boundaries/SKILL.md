---
name: windows-boundaries
description: Windows security-boundary attacks — kernel/user crossing (win32k/dxgkrnl UAF CVE-2025-24983/62573), BYOVD kernel R/W (CVE-2025-8061, EDRKillShifter), UAC/COM elevation (ICMLuaUtil/fodhelper), AppContainer/LPAC & Chromium-Mojo sandbox escape (CVE-2025-2783/4609), PPL bypass (BYOVDLL CVE-2023-28229), RPC/ALPC & named-pipe impersonation (PhantomRPC, Potato)
metadata:
  type: offensive
  phase: exploitation
  tools: WinDbg, OleViewDotNet, NtObjectManager, PrintSpoofer, GodPotato, PPLBlade, UACME, loldrivers, Sysmon
  mitre: TA0004
kill_chain:
  phase: [exploit, install]
  step: [4, 5]
  attck_tactics: [TA0002, TA0004, TA0005]
  attck_techniques: [T1068, T1211, T1548.002, T1134.001, T1134.002, T1543.003, T1559, T1112, T1003.001, T1014]
depends_on: [privesc-windows, exploit-development]
feeds_into: [red-team-ops, edr-evasion]
inputs: [sandbox_config, kernel_info, foothold_token]
outputs: [boundary_escape, elevated_access, kernel_rw_primitive, system_token]
references:
  - references/kernel-user-boundary.md
  - references/byovd-kernel-rw.md
  - references/integrity-uac-com.md
  - references/sandbox-appcontainer-escape.md
  - references/ppl-protected-process.md
  - references/rpc-alpc-boundary.md
scripts:
  - scripts/enum_boundaries.ps1
  - scripts/ioctl_fuzzer.py
  - scripts/byovd_kernel_rw.c
  - scripts/uac_com_elevate.cpp
  - scripts/sandbox_escape_probe.py
  - scripts/ppl_byovdll.c
  - scripts/named_pipe_impersonate.c
---

# Windows Security Boundaries

## When to Activate

- Planning a privilege-escalation path that crosses a Windows security boundary
  (integrity level, AppContainer/LPAC, PPL, or the kernel/user line)
- Sandbox-escape research: browser renderer (Chromium/Edge Mojo), Office WebView, packaged
  apps, AppContainer/LPAC brokers
- Reaching Ring 0 via win32k/dxgkrnl bugs or BYOVD for a kernel read/write primitive
- Defeating PPL to dump LSASS or tamper with EDR self-defense
- Going from a `SeImpersonate` service account to SYSTEM via RPC/ALPC/named-pipe abuse
- UAC bypass (Medium → High) via auto-elevating COM or registry hijack

## Boundary stack (high → low): VTL1 (Secure Kernel/Cred Guard) > Ring 0 (ntoskrnl/win32k/drivers) > Ring 3: System > High > Medium > Low > AppContainer/LPAC. PPL is an orthogonal wall guarding LSASS/EDR even from SYSTEM.

## Technique Map

| Technique | ATT&CK | CWE | Reference | Script |
|-----------|--------|-----|-----------|--------|
| win32k / dxgkrnl UAF → kernel R/W → token steal | T1068 | CWE-416 | references/kernel-user-boundary.md | scripts/ioctl_fuzzer.py |
| Driver IOCTL abuse (METHOD_NEITHER arb-R/W) | T1068 | CWE-781 | references/kernel-user-boundary.md | scripts/ioctl_fuzzer.py |
| BYOVD load + MSR/LSTAR or phys R/W → SYSTEM | T1068, T1543.003 | CWE-1188 | references/byovd-kernel-rw.md | scripts/byovd_kernel_rw.c |
| BYOVD EDR-kill (callback nulling) | T1562.001, T1014 | CWE-1188 | references/byovd-kernel-rw.md | scripts/byovd_kernel_rw.c |
| UAC bypass — ICMLuaUtil elevated COM moniker | T1548.002 | CWE-269 | references/integrity-uac-com.md | scripts/uac_com_elevate.cpp |
| UAC bypass — fodhelper HKCU registry hijack | T1548.002, T1112 | CWE-269 | references/integrity-uac-com.md | scripts/uac_com_elevate.cpp |
| AppContainer/LPAC broker abuse / cap over-grant | T1211 | CWE-668 | references/sandbox-appcontainer-escape.md | scripts/sandbox_escape_probe.py |
| Chromium/Edge Mojo IPC sandbox escape | T1211 | CWE-501 | references/sandbox-appcontainer-escape.md | scripts/sandbox_escape_probe.py |
| Named-object / symbolic-link squatting | T1211 | CWE-59 | references/sandbox-appcontainer-escape.md | scripts/sandbox_escape_probe.py |
| PPL bypass — BYOVDLL (old signed DLL into PPL) | T1003.001, T1211 | CWE-426 | references/ppl-protected-process.md | scripts/ppl_byovdll.c |
| PPL bypass — live-dump / WER / Protection-clear | T1003.001, T1562.001 | CWE-269 | references/ppl-protected-process.md | scripts/byovd_kernel_rw.c |
| RPC server spoof / endpoint squat (PhantomRPC) | T1559, T1134.001 | CWE-287 | references/rpc-alpc-boundary.md | scripts/named_pipe_impersonate.c |
| Named-pipe client impersonation (Potato family) | T1134.002, T1134.001 | CWE-294 | references/rpc-alpc-boundary.md | scripts/named_pipe_impersonate.c |
| Host boundary posture enumeration | T1082 | CWE-693 | (all) | scripts/enum_boundaries.ps1 |

## Quick Start

```cmd
:: 0. Map the host's boundary posture -> pick the right primitive
powershell -ep bypass -File scripts/enum_boundaries.ps1
::    reports: integrity, AppContainer, SeImpersonate/SeDebug, HVCI, driver blocklist,
::    LSASS RunAsPPL, drivers loaded from user-writable paths, named-pipe count.

:: 1. From a sandbox (renderer/packaged app): rank escape vectors
python scripts/sandbox_escape_probe.py

:: 2. Medium -> High: UAC bypass (no file dropped via COM moniker)
uac_com_elevate.exe com "C:\Windows\System32\cmd.exe /c whoami /groups > C:\poc.txt"

:: 3. SeImpersonate present -> SYSTEM via PhantomRPC endpoint squat
whoami /priv | findstr SeImpersonate
named_pipe_impersonate.exe \\.\pipe\W32TIME "C:\Windows\System32\cmd.exe"
w32tm /resync                          :: triggers the SYSTEM client to connect

:: 4. Need Ring 0: map a driver's IOCTLs, then BYOVD kernel R/W -> token steal
python scripts/ioctl_fuzzer.py --device RTCore64 --map
byovd_kernel_rw.exe C:\test\driver.sys token

:: 5. Dump LSASS under PPL without a driver (BYOVDLL / CNG KSP)
ppl_byovdll.exe register C:\stage\vuln_ncryptprov.dll GhostKsp
ppl_byovdll.exe trigger  GhostKsp
```

## OPSEC & Detection (summary)

| Technique | Telemetry / IOC | Detection (Sigma / EDR) | OPSEC note |
|-----------|-----------------|--------------------------|------------|
| win32k/dxgkrnl exploit | Bugcheck EID 1001 ref win32k/dxgkrnl; process token flips to S-1-5-18 with no service genealogy | Sigma on bugchecks + token anomaly; ETW Microsoft-Windows-Win32k | Prefer data-only token copy over CFG/CET-fighting control-flow hijack; missed race = loud bugcheck |
| BYOVD | Sysmon EID 6 driver load from user-writable path; 7045/4697 kernel service; EDR telemetry goes silent | Sigma on unusual driver path + known-bad hashes (loldrivers.io); driver-load-time window | Use un-blocklisted/HVCI-compatible driver; restore LSTAR/callbacks; DeleteService + del .sys |
| UAC bypass (COM/fodhelper) | Sysmon EID 13 write to HKCU ms-settings\Shell\Open\command; dllhost /Processid:{3E5FC7F9..} spawning shell | Elastic/ManageEngine ICMLuaUtil + fodhelper rules | Rotate to a less-known AutoElevate CLSID; don't spawn cmd from dllhost; clean HKCU tree |
| Sandbox escape | Renderer/GPU process spawning cmd/powershell/rundll32; Mojo handle-transfer anomalies | Sigma on browser child-process; patch-posture alert (Edge<134.0.3124.93) | Stay in-process post-escape (IPC layer is an EDR blind spot); symlink squat is mostly dead post-2017 |
| PPL bypass | Old keyiso/ncryptprov version loaded in lsass (EID 7); EID 10 lsass read; Cryptography\Providers write; live-dump | Sigma on DLL version-mismatch + GrantedAccess to lsass | Driverless (BYOVDLL/WER/live-dump) avoids BYOVD noise; restore Protection byte; obfuscate dumps |
| RPC/ALPC impersonation | 4624 logon type 9 (Advapi); SYSTEM child of service-acct parent; RPC_S_SERVER_UNAVAILABLE (EID 1) | Elastic named-pipe impersonation rule; ETW RPC + high impersonation level | PhantomRPC endpoint squat blends w/ admin triggers (w32tm/gpupdate); RevertToSelf + close pipe |

## Deep Dives

- **references/kernel-user-boundary.md** — Ring 3→Ring 0 via win32k/dxgkrnl UAF
  (CVE-2025-24983, CVE-2025-62573, CVE-2025-55224, CVE-2025-62221, CVE-2026-26132), driver
  IOCTL surface, kernel R/W → EPROCESS token steal / Protection clear / PreviousMode, modern
  no-PTE-self-map constraint, KDP/HVCI considerations.
- **references/byovd-kernel-rw.md** — Bring-Your-Own-Vulnerable-Driver: load signed driver,
  MSR-LSTAR vs physical-memory primitives (CVE-2025-8061), EDRKillShifter / Qilin driver
  rotation, 2025-2026 driver+CVE catalog, blocklist/HVCI bypass, driver-load detection.
- **references/integrity-uac-com.md** — integrity model, appinfo/autoElevate internals,
  fodhelper (UACME 33) + ICMLuaUtil/CMSTPLUA (UACME 41), 2025 IEditionUpgradeManager bypass,
  finding new AutoElevate COM classes, T1548.002 ITW campaigns.
- **references/sandbox-appcontainer-escape.md** — AppContainer/LPAC model + capabilities,
  broker abuse (WinRT XmlDocument), Chromium/Edge Mojo escapes (CVE-2025-2783 ForumTroll,
  CVE-2025-4609 ipcz), symbolic-link/RtlIsSandboxToken mitigation, 3-bug renderer chain.
- **references/ppl-protected-process.md** — PS_PROTECTION/signer levels, BYOVDLL "Ghost in
  the PPL" (CVE-2023-28229/36906, BCryptRegisterProvider), NtSystemDebugControl live-dump
  (Win11 23H2), WER dump, kernel Protection-clear, PPLBlade, Credential Guard hard stop.
- **references/rpc-alpc-boundary.md** — named-pipe client impersonation primitive, ALPC
  SQoS/RequiredServerSid, PhantomRPC server-spoof/endpoint-squat (2026, unpatched), Potato
  family (PrintSpoofer/GodPotato/SigmaPotato), WER ALPC LPE, NtObjectManager enumeration.
