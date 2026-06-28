# Windows Event-Log Hunting & Timeline Reconstruction

ATT&CK: T1070.001 (Clear Windows Event Logs), T1070 (Indicator Removal), T1059.001 (PowerShell),
T1078 (Valid Accounts), T1021 (Remote Services). CWE-778 (Insufficient Logging).

## Theory / Mechanism

Windows records the attack story across EVTX channels, the registry, and filesystem artifacts.
The DFIR workflow is: (1) **Sigma-hunt** the event logs for known-bad with a fast engine, then
(2) **parse** key artifacts into normalized CSV, then (3) **fuse** them into a single time-ordered
**super-timeline** for correlation. Three Rust/portable tools dominate, then plaso/Timesketch scale it.

High-value Event IDs (Security/Sysmon/System unless noted):
- **4624 / 4625 / 4648** logon success / fail / explicit creds (type 3 = network, 10 = RDP, 9 = NewCredentials)
- **4672** special privileges; **4720/4732/4728** account & group changes; **4768/4769** Kerberos TGT/TGS
- **4688** process creation (+ command line if audited); **Sysmon 1** with full cmdline + hashes
- **7045 / System** service install; **Sysmon 13** registry; **Sysmon 3** network; **Sysmon 11** file create
- **PowerShell 4104** ScriptBlock; **4103** module logging
- **1102 (Security) / 104 (System)** = **log cleared** → anti-forensics red flag (see anti-forensics ref)
- **TerminalServices-LocalSessionManager 21/25**, **RemoteConnectionManager 1149** = RDP

## Modern 2024-2026 currency (verified)

- **Hayabusa v3.x (Yamato Security)** — Sigma-based fast timeline generator with the broadest native
  Sigma support of any EVTX tool. Recent: event **de-duplication** (handles VSS/backup EVTX +
  recovered records), a **scan wizard**, Base64 extraction/decoding, alert-level adjustment for
  critical systems, and **Live Response packages (v2.18+)** — binary + XOR-encoded rules + config
  bundled to avoid AV triggers and **minimise writes to disk** (protects the USN journal on a live host).
- **Chainsaw v2 (WithSecure)** — Rust Sigma + custom-rule hunter; also builds a **Shimcache execution
  timeline enriched with Amcache**, parses **SRUM**, and dumps raw MFT/registry/ESE. v2 no longer
  bundles Sigma rules / EVTX-Attack-Samples — clone `SigmaHQ/sigma` separately for current logic.
- **Eric Zimmerman tools** — `EvtxECmd` (EVTX→CSV with maps), `MFTECmd`, `PECmd` (Prefetch),
  `AmcacheParser`, `AppCompatCacheParser` (ShimCache), `SrumECmd`, `RECmd`; `Timeline Explorer` for
  pivoting CSV.
- **plaso / log2timeline** ("super timeline all the things") → `.plaso` storage → `psort`/`psteal`.
  2025 trend: **targeted timelines** (parse only relevant artifacts) over kitchen-sink super-timelines
  to cut processing and analyst fatigue in time-critical (ransomware) cases.
- **Timesketch (Google)** — collaborative timeline analysis; ingests plaso/JSONL/CSV/KAPE/Velociraptor.
  **Dissect/Acquire (Fox-IT)** scales acquisition→timeline for enterprise fleets straight into Timesketch.

## Complete working commands

### Stage 1 — Sigma hunt (fast triage of EVTX)
```bash
# Chainsaw v2 (clone fresh Sigma first):
git clone https://github.com/SigmaHQ/sigma
chainsaw hunt /evidence/C/Windows/System32/winevt/Logs/ \
  -s sigma/rules/windows/ --mapping mappings/sigma-event-logs-all.yml \
  --level high --status stable -o /evidence/chainsaw.csv
# Chainsaw shimcache->amcache execution timeline + SRUM:
chainsaw analyse shimcache SYSTEM --amcache Amcache.hve -o shimcache_timeline.csv
chainsaw analyse srum SRUDB.dat SOFTWARE -o srum.csv

# Hayabusa v3 timeline (UTC-bounded to incident window, output for Timeline Explorer):
hayabusa csv-timeline -d /evidence/.../winevt/Logs -p super-verbose \
  --timeline-start "2026-06-01 00:00:00 +00:00" --timeline-end "2026-06-15 00:00:00 +00:00" \
  -o /evidence/hayabusa.csv --RFC-3339
hayabusa metrics -d /evidence/.../winevt/Logs        # event-id frequency sanity check
```

### Stage 2 — parse key artifacts to CSV (Eric Zimmerman)
```cmd
EvtxECmd.exe -d "C:\Windows\System32\winevt\Logs" --csv out --csvf evtx.csv
MFTECmd.exe -f "$MFT" --csv out --csvf mft.csv
MFTECmd.exe -f "$Extend\$J" -m "$MFT" --csv out --csvf usn.csv
PECmd.exe -d "C:\Windows\Prefetch" --csv out --csvf prefetch.csv
AmcacheParser.exe -f "C:\Windows\AppCompat\Programs\Amcache.hve" -i --csv out
AppCompatCacheParser.exe -f SYSTEM --csv out --csvf shimcache.csv
SrumECmd.exe -d "C:\Windows\System32\sru" -r SOFTWARE --csv out   # net usage per app
```

### Stage 3 — super / targeted timeline + Timesketch
```bash
# Targeted timeline (recommended): only the parsers that matter, off a mounted image:
log2timeline.py --parsers "winevtx,mft,prefetch,amcache,appcompatcache,winreg,usnjrnl" \
  /evidence/case.plaso /evidence/image.E01
psort.py -o l2tcsv /evidence/case.plaso \
  --slice "2026-06-10T00:00:00" --slice_size 96 -w /evidence/timeline.csv
# Push to Timesketch for collaborative analysis:
timesketch_importer --sketch_id 7 -u admin -p '***' --host http://ts:5000 /evidence/case.plaso
# Enterprise fleet (Fox-IT Dissect → Timesketch):
target-query -f evt,registry,filesystem.timeline targets/*.tar | \
  timesketch_importer --sketch_id 7 -
```

## Detection

```yaml
title: Windows Event Log Cleared (anti-forensics)
id: e1102-104-clear-ir
status: stable
logsource: { product: windows }
detection:
  security_cleared:
    EventID: 1102          # Security log cleared (channel: Security)
  system_cleared:
    Provider_Name: 'Microsoft-Windows-Eventlog'
    EventID: 104           # any log cleared (channel: System)
  condition: security_cleared or system_cleared
fields: [SubjectUserName, Channel]
level: high
```

Additional detections to run as Sigma during the hunt: 4625 spray (many fails one source),
4648 explicit-cred lateral movement, 7045 + Sysmon 1 unsigned service binary, 4104 obfuscated
PowerShell, 1149/21 RDP from new geos. Gaps in **EventRecordID** sequence within a channel indicate
selective record deletion even when 1102/104 are absent.

## OPSEC

- **Touches:** read-only on collected EVTX/artifacts. On a **live** host, prefer Hayabusa Live
  Response packages (XOR-encoded rules, minimal disk writes) to avoid corrupting the USN journal and
  to dodge AV quarantine of the rules file.
- **Cleanup:** none for offline parsing; remove decoded Base64/credential material from work dir
  after the case.
- **Evasion awareness:** if logs were cleared, pull EVTX from **VSS** or the raw disk image — never
  trust the tampered live channel. Correlate cleared windows against `$LogFile`/USN and other
  execution artifacts (Prefetch/Amcache) that the attacker may have missed.

## References

- Hayabusa — github.com/Yamato-Security/hayabusa (v3.x; Live Response packages v2.18+)
- Chainsaw — github.com/WithSecureLabs/chainsaw (v2) ; SigmaHQ/sigma
- Eric Zimmerman tools — ericzimmerman.github.io ; Timeline Explorer
- plaso/log2timeline — github.com/log2timeline/plaso ; Timesketch — github.com/google/timesketch
- Hunt & Hackett "Scalable forensics timeline analysis using Dissect and Timesketch"
