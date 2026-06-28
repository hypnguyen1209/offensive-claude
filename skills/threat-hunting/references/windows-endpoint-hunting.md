# Windows Endpoint Hunting — Sysmon 15, ETW/AMSI Tamper, LOLBins, Credential Access

## Theory / Mechanism

Most post-exploitation activity surfaces on the endpoint before it reaches the network.
The richest free telemetry is **Sysmon** (driver-based) plus the native Windows **ETW**
providers (PowerShell ScriptBlock, Security auditing, Threat-Intelligence). ETW is a
kernel publish-subscribe bus; providers emit structured events, consumers subscribe.
Modern EDR is largely an ETW consumer, which is exactly why attackers attack ETW itself.

Key Sysmon event IDs to anchor hunts:

| EID | Event | Primary hunt use |
|-----|-------|------------------|
| 1   | Process create | Parent/child anomalies, LOLBins, command-line obfuscation |
| 3   | Network connect | Beacon dest, LOLBin → internet |
| 7   | Image load | Unsigned/odd DLL into LSASS, sideloading |
| 8   | CreateRemoteThread | Classic injection |
| 10  | ProcessAccess | LSASS handle requests (cred dumping) |
| 11  | File create | Dropper, `.dmp`, staging dirs |
| 12/13 | Registry | Run keys, ETW provider disable, service install |
| 17  | Pipe create | C2 named-pipe patterns |
| 22  | DNS query | Tunneling, DGA, C2 resolution |
| 25  | **ProcessTampering** | Process hollowing / herpaderping / ETW patch fallout |

## Sysmon 15 self-protection (PPL) and detecting its bypass

Since **Sysmon 15**, the Sysmon process runs as **Protected Process Light (PPL)**, which
blocks the classic `SysmonEnte`-style injection that previously blinded it. Killing the
agent is now the cheaper attacker path, so hunt for stop/unload:

- `System` log `7036` "Sysmon stopped" / `7034` unexpected service stop.
- `4799` / service deletion of `Sysmon64` or driver `SysmonDrv`.
- `fltMC unload` of the Sysmon minifilter (`SysmonDrv`).
- A previously chatty host going silent (visibility-gap rule in `methodology-hunt-loop.md`).

A modern, maintained Sysmon config (SwiftOnSecurity / Olaf Hartong `sysmon-modular` lineage)
is provided in `scripts/sysmon_config_2025.xml`: EID 25 enabled, LSASS ProcessAccess with
call-trace, ETW-tamper image loads, named-pipe and DNS logging, with high-volume noise
excluded. Note Microsoft is moving Sysmon-equivalent events (25 ProcessTampering, 7 Image
Load) into native OS ETW; the config remains the broadest free baseline today.

## ETW / AMSI patching detection (T1562.001, CWE-693)

The most common userland blind is patching `EtwEventWrite` / `NtTraceEvent` and AMSI's
`AmsiScanBuffer` in the current process so events/scans are never emitted. The patch writes
to normally read-only `.text` in `ntdll.dll` / `amsi.dll`, which requires a `VirtualProtect`
flip to RWX/RW first. That memory mechanics is the detectable signal.

**Detection approaches (defense in depth — userland patching defeats a single source):**

1. **Sysmon EID 25 (ProcessTampering)** — Windows 10 21H1+ catches hollowing/herpaderping
   and frequently the side-effects of in-memory image patching.
2. **ProcessAccess / image-load to ntdll/amsi** — config a rule for EID 10 where the target
   is `ntdll.dll`/`amsi.dll` and the call stack originates from `kernelbase.dll`
   (`VirtualProtect`), creating an audit trail of the patch.
3. **AMSI bypass artifacts** — PowerShell ScriptBlock (EID 4104) containing
   `AmsiScanBuffer`, `amsiInitFailed`, `[Ref].Assembly.GetType('...AmsiUtils')`,
   `Marshal.Copy`/`VirtualProtect` reflection.
4. **Kernel-context ETW-TI** — the `Microsoft-Windows-Threat-Intelligence` provider needs a
   kernel driver to consume (callback model, not standard session). Only EDR with a driver
   sees it, and it is emitted *after* the operation, so userland patching cannot suppress it.
   Audit provider health to spot system-wide ETW disruption.

```powershell
# Enumerate active ETW providers and flag missing security providers (run periodically)
logman query providers | Select-String -Pattern "Threat-Intelligence|PowerShell|Sysmon|DNS-Client"
# If 'Microsoft-Windows-Threat-Intelligence' / security providers vanish vs. baseline -> investigate
```

```yaml
title: AMSI / ETW In-Memory Patch Indicators
id: a2f4c1b9-7e3d-4c6a-8b21-9f0e1d2c3b4a
status: experimental
description: PowerShell content patching AMSI/ETW or flipping ntdll/amsi memory protections
logsource:
    product: windows
    category: ps_script
detection:
    amsi:
        ScriptBlockText|contains:
            - 'AmsiScanBuffer'
            - 'amsiInitFailed'
            - 'AmsiUtils'
    etw:
        ScriptBlockText|contains:
            - 'EtwEventWrite'
            - 'NtTraceEvent'
    mech:
        ScriptBlockText|contains:
            - 'VirtualProtect'
            - 'Marshal.Copy'
            - 'GetProcAddress'
    condition: (amsi or etw) and mech
falsepositives:
    - Security research / red-team tooling in sanctioned labs
level: high
tags: [attack.defense_evasion, attack.t1562.001, attack.t1562.002]
```

IOCs: RWX private regions in `ntdll`/`amsi` ranges; `EtwEventWrite` first bytes patched to
`ret`/`xor eax,eax;ret`; unbacked return addresses on the syscall stack (stack-frame
analysis). Note SilentMoonwalk-style stack spoofing mitigates unbacked-stack detection;
current EDR signatures specifically target SilentMoonwalk unwind-info patterns.

## LOLBins and process-tree anomalies (T1059, T1218, CWE-78)

Living-off-the-land binaries (signed Microsoft binaries abused for download/exec/proxy
execution) remain the dominant evasion. Hunt the *combination* of LOLBin + network/decode
flags, and abnormal parent/child relationships.

```yaml
title: LOLBin Download or Proxy Execution
id: c7d8e9f0-1a2b-3c4d-5e6f-7a8b9c0d1e2f
status: stable
logsource: { product: windows, category: process_creation }
detection:
    lolbins:
        Image|endswith:
            - '\certutil.exe'
            - '\mshta.exe'
            - '\regsvr32.exe'
            - '\rundll32.exe'
            - '\msiexec.exe'
            - '\wmic.exe'
            - '\cmstp.exe'
            - '\msxsl.exe'
            - '\bitsadmin.exe'
            - '\curl.exe'
    suspicious:
        CommandLine|contains:
            - 'http'
            - 'ftp'
            - '\\\\'
            - '-urlcache'
            - '-decode'
            - 'scrobj.dll'
            - '/i:http'
    condition: lolbins and suspicious
level: high
tags: [attack.execution, attack.defense_evasion, attack.t1218, attack.t1105]
```

Anomalous process trees to hunt (parent → child):

```
winword.exe / excel.exe  -> cmd.exe / powershell.exe   # macro / phishing payload
outlook.exe              -> powershell.exe / mshta.exe  # phishing payload
w3wp.exe / sqlservr.exe  -> cmd.exe                     # webshell / SQLi RCE
wmiprvse.exe             -> powershell.exe               # WMI lateral movement
services.exe             -> non-System32 service binary  # persistence / PsExec-like
mshta.exe / rundll32.exe -> spawning lsass-touching tool
```

KQL (Defender/Sentinel) frequency-anomaly hunt for AD recon LOLBins:

```kql
let recon = dynamic(["net.exe","net1.exe","nltest.exe","dsquery.exe","whoami.exe",
    "quser.exe","tasklist.exe","systeminfo.exe","csvde.exe","arp.exe"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ (recon)
| summarize cnt = count(), tools = make_set(FileName) by DeviceId, DeviceName, bin(Timestamp, 1h)
| where cnt > 10 and array_length(tools) >= 4   // burst of distinct recon tools in 1h
| order by cnt desc
```

## Credential access — LSASS handle hunting (T1003.001, CWE-522)

Dumping LSASS is the highest-value credential-access primitive. The signal is a non-system
process opening a handle to `lsass.exe` with read/dump access masks.

```yaml
title: Suspicious LSASS Access (Credential Dumping)
id: 7b2e4f1a-9c3d-4e5f-8a6b-1c2d3e4f5a6b
status: stable
logsource: { product: windows, category: process_access }
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess:
            - '0x1010'   # QUERY_LIMITED_INFO + VM_READ
            - '0x1410'
            - '0x1438'   # full read for dump
            - '0x143a'
            - '0x1fffff' # PROCESS_ALL_ACCESS
    filter_system:
        SourceImage|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Program Files\Windows Defender\'
            - 'C:\Program Files\Microsoft Defender'
    condition: selection and not filter_system
level: high
tags: [attack.credential_access, attack.t1003.001]
```

KQL pairing LSASS access with a `.dmp` write (comdump/MiniDumpWriteDump path):

```kql
DeviceProcessEvents
| where FileName =~ "lsass.exe" or InitiatingProcessFileName =~ "lsass.exe"
| join kind=inner (
    DeviceFileEvents
    | where ActionType == "FileCreated" and FileName endswith ".dmp"
) on DeviceId
| project Timestamp, DeviceName, InitiatingProcessFileName, FolderPath, FileName
```

Also hunt **comsvcs.dll MiniDump** (`rundll32 comsvcs.dll MiniDump <pid> out.dmp full`),
direct/indirect syscalls bypassing the ntdll userland stub (unbacked syscall stack), and
PPL-bypass drivers (BYOVD, T1068) loading just before LSASS access.

The `scripts/evtx_hunt.py` tool runs all of the above as offline analytics over collected
EVTX (Sysmon Operational + Security + PowerShell) without a SIEM — useful for IR triage.

## Detection summary

| Behavior | Telemetry / IOC | Detection |
|----------|-----------------|-----------|
| ETW/AMSI patch | RWX in ntdll/amsi; ScriptBlock w/ AmsiScanBuffer | Sigma above; EID 25; ETW-TI; logman provider audit |
| Sysmon kill | 7036/7034, SysmonDrv unload, EPS drop | Visibility-gap metric; service-state monitoring |
| LSASS dump | EID 10 to lsass + `.dmp` write | LSASS-access Sigma + dmp join |
| LOLBin abuse | certutil/mshta/regsvr32 + http/decode | LOLBin Sigma; tree anomalies |
| Injection | EID 8 cross-process; EID 25 | CreateRemoteThread, ProcessTampering |

## OPSEC (analyst)

- LSASS-access rules false-positive on EDR/AV themselves — baseline your own security
  stack's `SourceImage` set before alerting, or you will drown the SOC.
- ETW-TI requires a kernel driver; if your EDR lacks one, treat userland ETW as
  *advisory* and lean on Sysmon EID 25 + behavioral correlation.
- Hunt over collected EVTX offline first (`evtx_hunt.py`) to avoid touching live hosts and
  tipping an EDR-aware operator.

## References

- "Sysmon Configuration 2025: Catch Advanced Threats" — onlinehashcrack, 2025.
- Olaf Hartong, "Sysmon vs Microsoft Defender for Endpoint, MDE Internals 0x01" — FalconForce, 2024.
- "Silence The EDR: A Red Teamer's Guide To ETW Patching And Evasion" — Undercode Testing, 2025.
- "Stealth Syscall Execution: Bypassing ETW, Sysmon, and EDR Detection" — DarkRelay, 2025.
- "Windows Event Tracing with Logman: A Threat Hunter's Guide" — justruss.tech, Aug 2025.
- TrustedSec Sysmon Community Guide; SwiftOnSecurity sysmon-config; Olaf Hartong sysmon-modular.
- MITRE ATT&CK T1562.001 / T1003.001 / T1218.
