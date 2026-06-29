# Dynamic-Code Mitigations: ACG / CIG / Code Integrity Guard

Cluster on the mitigations that stop an exploit from *introducing new executable code* into a
process: **Arbitrary Code Guard (ACG)**, **Code Integrity Guard (CIG)**, and the broader
**Dynamic Code** policy. These are the defining mitigations of hardened browser/renderer
processes (Edge content process, Chrome with `--win-renderer`, EMET-style hardened apps).

## Theory / Mechanism

| Mitigation | Policy enum | Blocks | Allows |
|------------|-------------|--------|--------|
| ACG (Arbitrary Code Guard) | `ProcessDynamicCodePolicy.ProhibitDynamicCode` | `VirtualAlloc(PAGE_EXECUTE_*)`, `VirtualProtect`→executable, `MapViewOfFile` w/ execute, `WriteProcessMemory` to RX | loading signed images; existing RX | 
| CIG (Code Integrity Guard) | `ProcessSignaturePolicy.MicrosoftSignedOnly` / `StoreSignedOnly` | loading non-Microsoft / unsigned DLLs | loading MS- or Store-signed images |
| Dynamic Code (per-thread opt-out) | `ProcessDynamicCodePolicy.AllowThreadOptOut` | n/a | a thread may call `SetThreadInformation(ThreadDynamicCodePolicy)` to opt out (if app enabled opt-out) |

Together ACG + CIG mean: **you cannot generate new code, and you cannot load arbitrary signed-
elsewhere code** — only Microsoft/Store-signed images and the code already mapped at load time can
ever execute. This is the worst case for shellcode injection.

### Fingerprinting
```c
PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dc;
GetProcessMitigationPolicy(h, ProcessDynamicCodePolicy, &dc, sizeof dc);
// dc.ProhibitDynamicCode  = ACG on
// dc.AllowThreadOptOut    = per-thread opt-out permitted (a weakness)
// dc.AllowRemoteDowngrade = remote process can downgrade (rare, a weakness)
PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sig;
GetProcessMitigationPolicy(h, ProcessSignaturePolicy, &sig, sizeof sig);
// sig.MicrosoftSignedOnly = CIG on (MS only)
```
`scripts/Get-ProcessMitigationMap.ps1` surfaces `ProhibitDynamicCode` and `MicrosoftSignedOnly`
per process and flags any with `AllowThreadOptOut`/`AllowRemoteDowngrade`.

## Bypass Techniques

### 1. Signed-code reuse only (ROP/JOP) — the rule, not the exception
Under ACG you never make new executable memory; you reuse existing RX code. The entire payload is
a ROP/JOP chain over already-mapped signed modules (see memory-safety-mitigations.md for the chain
mechanics). Combine with a data-only objective where possible so no code-execution primitive is
needed at all.

### 2. Per-thread Dynamic Code opt-out
If the process set ACG with `AllowThreadOptOut = TRUE` (some apps do, for plugin compatibility),
a thread you control can lift ACG for itself:
```c
// Runs INSIDE the target after you have code-flow control on a thread.
PROCESS_MITIGATION_DYNAMIC_CODE_POLICY tdc = {0};
tdc.ProhibitDynamicCode = 0;            // request opt-out for this thread
SetThreadInformation(GetCurrentThread(), ThreadDynamicCodePolicy, &tdc, sizeof tdc);
// now VirtualProtect to RX / VirtualAlloc RWX succeeds on this thread
```
Only works when the app enabled opt-out; check `AllowThreadOptOut` during recon.

### 3. JIT / browser exemption
JIT engines must emit executable code, so the JIT path is exempted — modern browsers run the JIT
compiler in a **separate, less-restricted JIT process** and map the result read-only into the
content process via a shared section. Two angles:
- Compromise/abuse the JIT process (which lacks full ACG) to emit attacker-controlled "JIT" code,
  which then maps executable into the ACG content process.
- Pivot: inject into any cooperating helper process that does not have ACG and operate from there.

### 4. SEC_IMAGE section abuse
Create a section with `SEC_IMAGE` so the OS treats it as a module image (modules get execute even
under ACG). The catch is CIG: the "image" must pass code-integrity (be MS/Store-signed) if CIG is
on. Without CIG, an attacker-controlled but well-formed PE mapped `SEC_IMAGE` can become RX.
```c
// Map an on-disk PE as an image section -> pages get execute even under ACG.
HANDLE hFile = CreateFileW(L"signed_or_crafted.dll", GENERIC_READ, FILE_SHARE_READ,
                           0, OPEN_EXISTING, 0, 0);
HANDLE hSec; NTSTATUS s = NtCreateSection(&hSec, SECTION_ALL_ACCESS, NULL, NULL,
                           PAGE_READONLY, SEC_IMAGE, hFile);
PVOID base = NULL; SIZE_T vs = 0;
NtMapViewOfSection(hSec, GetCurrentProcess(), &base, 0, 0, NULL, &vs, ViewShare, 0,
                   PAGE_READONLY);  // mapped image pages are executable
// With CIG on, NtCreateSection(SEC_IMAGE) fails for non-MS/Store-signed files.
```

### 5. Cross-process pivot (most reliable in practice)
Find a process **without** ACG/CIG (a legacy helper, an updater, an old non-MS app), inject
shellcode there normally, and have it operate on the hardened target (read its memory, drive it
via IPC, or just achieve the objective from the un-mitigated context). Pair with
`scripts/Get-ProcessMitigationMap.ps1` output to pick the weakest neighbor.

## Detection

```yaml
title: ACG/CIG Bypass - Unbacked Executable or SEC_IMAGE of Unusual File
id: 2b8d4f6e-1a3c-4e7b-8d9f-0a1b2c3d4e5f
status: experimental
logsource:
  product: windows
  category: process_access
detection:
  # 1) per-thread ACG opt-out is rare and high-signal
  thread_optout:
    EventType: 'SetThreadInformation'
    InfoClass: 'ThreadDynamicCodePolicy'
  # 2) image-section map of a file from a user-writable / temp path in a hardened proc
  sec_image_temp:
    CallTrace|contains: 'NtCreateSection'
    TargetFilename|contains:
      - '\AppData\Local\Temp\'
      - '\Users\Public\'
  condition: thread_optout or sec_image_temp
falsepositives: [browsers JIT, .NET ReadyToRun, legitimate updaters]
level: high
```
Telemetry/IOCs: EDR sees executable memory whose backing is not a signed image (unbacked RX), or
a `SEC_IMAGE` section created from a non-image-cache / user-writable path; ETW image-load events
for DLLs outside `System32`/program dirs; CIG blocks log as `STATUS_INVALID_IMAGE_HASH`
(0xC0000428) and Code Integrity Operational EID 3033 (image failed integrity).

## OPSEC

- The cross-process pivot is the quietest path — it removes the need to defeat ACG/CIG at all, but
  remote injection (`CreateRemoteThread`, `QueueUserAPC`, mapping injection) into the helper is
  itself watched; prefer process-hollow/early-bird into a process you legitimately spawned.
- `SEC_IMAGE` from a temp path is a strong IOC; if CIG is off, sideload through a normal program
  directory rather than `%TEMP%`.
- Per-thread opt-out is rare in the wild → very high signal if logged; only use when recon proves
  `AllowThreadOptOut`.
- Leaving RWX in a content process that "shouldn't" have it (ACG-protected) is anomalous by
  definition — keep the dynamic-code window minimal and restore protections.

## References

- Microsoft Learn — *Customize exploit protection / Process mitigation policies* (ACG, CIG, Dynamic Code): https://learn.microsoft.com/en-us/defender-endpoint/customize-exploit-protection
- Microsoft Learn — `PROCESS_MITIGATION_DYNAMIC_CODE_POLICY` / `PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY` (Win32 API): https://learn.microsoft.com/en-us/windows/win32/api/winnt/
- IBM X-Force — *Operationalizing browser exploits to bypass WDAC* (V8/JIT in browser context, RWX-looks-normal): https://www.ibm.com/think/x-force/operationalizing-browser-exploits-to-bypass-wdac
