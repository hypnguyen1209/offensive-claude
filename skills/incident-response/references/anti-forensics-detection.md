# Anti-Forensics Detection — Timestomp, Log/Journal Tamper, Deletion, VSS

ATT&CK: T1070.006 (Timestomp), T1070.001 (Clear Windows Event Logs), T1070.002 (Clear Linux/Mac
Logs), T1070.004 (File Deletion), T1070.008 (Clear Mailbox Data), T1485 (Data Destruction),
T1490 (Inhibit System Recovery). CWE-778 (Insufficient Logging).

## Theory / Mechanism

Attackers manipulate evidence to break timelines and hide artifacts. The defender's edge is
**redundancy + cross-validation**: a single attribute can be forged, but the NTFS/USN/$LogFile
trio and Volume Shadow Copies preserve corroborating truth that most actors miss.

### Timestomping ($STANDARD_INFORMATION vs $FILE_NAME)
Every `$MFT` record carries **two** timestamp sets:
- **$SI (0x10)** — the times Explorer/`dir` show; **easily** set via Win32 `SetFileTime` (what
  `timestomp`, Cobalt Strike `timestomp`, and most tooling modify).
- **$FN (0x30)** — copied by the kernel from $SI at create/rename; **not** settable via the normal
  API, so it usually retains the *true* creation time.

Heuristics that flag timestomping:
- **$SI.Created < $FN.Created** (file claims to be older than its own MFT name record) — classic.
- **$SI sub-second nanoseconds == 0** (e.g. `...000000`) while $FN has precision — many timestomp
  tools zero the fractional seconds.
- **$SI.Created later than $SI.Modified/Accessed** by a wide margin, or all four $SI times identical.
- USN shows a **FILE_CREATE / FILE_RENAME** at time *T*, but $SI.Created ≠ *T*.

### Log / journal clearing
- Windows: **EventID 1102** (Security cleared), **104** (other channel cleared); gaps in
  **EventRecordID** sequence = selective deletion. `wevtutil cl <log>` is the common command.
- Linux: truncated/rotated `/var/log/*`, missing journald entries, `~/.bash_history` cleared or
  `HISTFILE` unset — but `linux.bash` recovers history from RAM.
- NTFS **$LogFile** (transaction log) and **$UsnJrnl** retain operation fragments even after the
  $MFT record is reused; `$LogFile` can hold filenames of files whose MFT entries were overwritten.

### Secure deletion / data destruction
- SDelete / CCleaner leave **rename patterns** (e.g. `AAAA....`, `ZZZZ`) in USN before delete; mass
  rename+delete of many files with known extensions in a short window = ransomware/wiper (T1485).
- `fsutil usn deletejournal` / clearing `$J` itself is an anti-forensic tell.

### Volume Shadow Copies (recovery)
VSS snapshots can contain **older $MFT, registry hives, and files** from before the tamper — the
single most valuable fallback when the live filesystem has been scrubbed. (Conversely, attackers
delete VSS via `vssadmin delete shadows /all` → T1490, itself an IOC.)

## Modern 2024-2026 currency (verified)

- **MFTECmd (Eric Zimmerman)** remains the standard `$MFT`/`$J` parser; the canonical timestomp check
  is **`Created0x10` (=$SI) vs `Created0x30` (=$FN)** in its CSV. It also parses `$UsnJrnl:$J` for the
  operation history.
- **2025 USN tooling advances** — purpose-built parsers (e.g. `usnjrnl-forensic`, SecurityRonin)
  implement the **CyberCX Rewind** algorithm for 100% path reconstruction even on reused MFT entries,
  and **QuadLink** correlation (extends David Cowen's **TriForce** = $MFT + $LogFile + $UsnJrnl with
  `$MFTMirr` integrity), plus built-in **anti-forensics detectors** for SDelete/CCleaner rename
  patterns, $LogFile gaps/ghost records, ransomware mass-rename, and timestomping (cross-validating
  $SI vs $FN vs USN FILE_CREATE). Works from a raw image/E01, cross-platform.
- **VSS access** at scale via `vss_carver`, or mount with `vshadowmount` (libvshadow) and re-parse the
  historical `$MFT`/hives.

## Complete working commands

### Detect timestomping from MFT + USN
```bash
# Parse on Windows (EZ MFTECmd), then run the cross-validator (see scripts/):
MFTECmd.exe -f "$MFT"        --csv out --csvf mft.csv
MFTECmd.exe -f "$Extend\$J"  -m "$MFT" --csv out --csvf usn.csv
python3 scripts/timestomp_detect.py --mft out/mft.csv --usn out/usn.csv --out findings.csv
# Quick manual triage in Timeline Explorer: filter where Created0x10 != Created0x30,
# or where SI nanoseconds are .0000000 but FN has precision.
```

### Detect log clearing
```cmd
:: Did someone clear logs?  (1102 Security, 104 any channel)
wevtutil qe Security "/q:*[System[(EventID=1102)]]" /f:text /c:5
wevtutil qe System   "/q:*[System[(EventID=104)]]"  /f:text /c:5
```
```bash
# EventRecordID gap check on a single channel (selective deletion even without 1102):
EvtxECmd.exe -f Security.evtx --csv out --csvf sec.csv
python3 - <<'PY'
import csv
ids=[int(r['RecordNumber']) for r in csv.DictReader(open('out/sec.csv',encoding='utf-8-sig')) if r['RecordNumber'].isdigit()]
ids.sort()
gaps=[(a,b) for a,b in zip(ids,ids[1:]) if b-a>1]
print("Record-ID gaps (possible deletion):", gaps[:20])
PY
```

### Recover from Volume Shadow Copies (the live FS was scrubbed)
```bash
# Linux examiner mounting a Windows image's VSS:
sudo vshadowmount /evidence/image.raw /mnt/vss      # exposes vss1, vss2 ...
sudo mount -o ro,loop,show_sys_files /mnt/vss/vss1 /mnt/shadow
# Re-parse the historical $MFT from before the tamper:
MFTECmd.exe -f /mnt/shadow/'$MFT' --csv out --csvf mft_vss1.csv
```
```cmd
:: Windows live: list shadows, expose one, diff $MFT/registry against current
vssadmin list shadows
mklink /d C:\vss1 \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```

## Detection

```yaml
title: Indicator Removal - timestomp / log clear / VSS delete
id: antiforensics-cluster-ir
status: stable
logsource: { product: windows }
detection:
  log_clear:
    EventID: [1102, 104]
  vss_delete:                      # Sysmon 1 / 4688 cmdline
    CommandLine|contains|all: ['vssadmin', 'delete', 'shadows']
  usn_delete:
    CommandLine|contains|all: ['fsutil', 'usn', 'deletejournal']
  timestomp_tool:
    CommandLine|contains:
      - 'timestomp'
      - 'Set-ItemProperty -Path * -Name CreationTime'
  condition: log_clear or vss_delete or usn_delete or timestomp_tool
level: high
falsepositives: [legitimate backup/cleanup maintenance windows]
```

Host IOCs: `$SI`≠`$FN` create time; zeroed `$SI` sub-second; EventRecordID gaps; SDelete/CCleaner
rename patterns in `$J`; `$LogFile` gaps + ghost records; mass same-extension rename/delete bursts.

## OPSEC

- **Touches:** mounting VSS read-only; parsing copies. Always work from a **forensic image copy** so
  you don't add USN/MFT entries to the original by examining it live.
- **Cleanup:** unmount VSS (`vssadmin`/`vshadowmount -u`); remove temporary symlinks (`C:\vss1`).
- **Evasion awareness:** anchor your timeline to the **hardest-to-forge** sources — $FN, USN
  FILE_CREATE, $LogFile, and VSS history — and explicitly note in the report where $SI is untrusted.
  Don't conclude "no activity" from a cleared log; prove absence with corroborating artifacts.

## References

- "Mastering the MFT … MFTECmd" — deaddisk.com ; Eric Zimmerman tools
- usnjrnl-forensic (CyberCX Rewind + QuadLink/TriForce) — github.com/SecurityRonin/usnjrnl-forensic
- David Cowen — TriForce ($MFT/$LogFile/$UsnJrnl) methodology
- libvshadow / vshadowmount — github.com/libyal/libvshadow
- SoK: Anti-Forensics Concepts and Research Practices (2026), arXiv 2604.05770
