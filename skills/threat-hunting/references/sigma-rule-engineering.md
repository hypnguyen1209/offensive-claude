# Sigma Rule Engineering, Correlation & EVTX Triage

## Theory / Mechanism

**Sigma** is the vendor-neutral YAML detection format: write once, compile to any SIEM
backend (Splunk SPL, Elastic ES|QL/Lucene, Microsoft 365 Defender KQL, Sentinel,
QRadar, etc.). ATT&CK tells you *what* to detect; Sigma encodes *how*; a backend
(`pySigma`) emits the *native query*. This is the unit of work in detection engineering.

Sigma's official repo classifies rules into three buckets that map to hunt maturity:

| Type | Purpose | When you write it |
|------|---------|-------------------|
| **Generic detection** | Detect a behavior/implementation of a technique | Durable baseline coverage |
| **Threat hunting** | Surface known-suspicious activity for review (noisier) | Active hunt, low-confidence lead |
| **Emerging threats** | Timely 0-day / campaign / malware IOCs | Fresh CTI, short shelf-life |

Choose rules earlier in the kill chain (Initial Access / Execution) to drive down
**MTTD** — catching delivery beats catching exfiltration.

## Anatomy of a high-quality rule

```yaml
title: Suspicious PowerShell Encoded Download Cradle
id: 0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b   # MUST be a unique UUID
status: experimental                        # experimental -> test -> stable
description: PowerShell with encoded command and a download primitive (IEX/DownloadString)
references:
    - https://attack.mitre.org/techniques/T1059/001/
author: detection-eng
date: 2026/06/28
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith: '\powershell.exe'
    enc:
        CommandLine|contains:
            - '-enc'
            - '-encodedcommand'
            - 'frombase64string'
    dl:
        CommandLine|contains:
            - 'DownloadString'
            - 'DownloadFile'
            - 'Invoke-WebRequest'
            - 'IEX'
            - 'Invoke-Expression'
    condition: selection_img and (enc or dl)
falsepositives:
    - IT automation / software deployment
level: high
tags:
    - attack.execution
    - attack.t1059.001
    - attack.command_and_control
    - attack.t1105
```

Engineering rules of thumb:
- **One UUID per rule, never reuse.** CI must fail on duplicate IDs.
- **Always tag ATT&CK** at technique granularity (`attack.t1059.001`), and note the v18
  Detection Strategy where it sharpens the analytic.
- Use `selection`/`filter` separation so the `condition` reads as English.
- Set `level` honestly — most "critical" rules belong at "medium". Alert fatigue is the
  bigger risk than a single missed event; rely on correlation for high-confidence alerts.
- Provide `falsepositives` — an untriaged rule is an unowned rule.

## Correlation rules (Sigma correlation spec)

Modern Sigma supports **correlation** (`event_count`, `value_count`, `temporal`,
`temporal_ordered`) for multi-event detections that single rules cannot express — e.g.,
"N kerberoast TGS-REQ from one host in 5 min" or "AS-REP roast *then* lateral logon".

```yaml
# Rule 1 (referenced by correlation)
title: Kerberos RC4 TGS Request
id: 1a1a1a1a-0000-0000-0000-000000000001
logsource: { product: windows, service: security }
detection:
    sel:
        EventID: 4769
        TicketEncryptionType: '0x17'   # RC4 = downgrade / roastable
    filter:
        ServiceName|endswith: '$'       # machine accounts
    condition: sel and not filter
---
# Correlation: many distinct SPNs roasted from one source in a short window
title: Kerberoasting Burst (Correlation)
id: 2b2b2b2b-0000-0000-0000-000000000002
correlation:
    type: value_count
    rules:
        - 1a1a1a1a-0000-0000-0000-000000000001
    group-by:
        - IpAddress
        - TargetUserName
    timespan: 5m
    condition:
        gte: 5
        field: ServiceName       # >=5 distinct SPNs
level: high
tags: [attack.credential_access, attack.t1558.003]
```

Other high-value correlation/Sigma rules to keep in the pack (full-fidelity, paste-ready):

```yaml
title: DCSync from Non-DC (DRSUAPI Replication)
id: 5a6c7e3b-8d4f-4a2e-9c1b-7f3e8d2a1b4c
status: stable
logsource: { product: windows, service: security }
detection:
    selection:
        EventID: 4662
        Properties|contains:
            - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes
            - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes-All
    filter:
        SubjectUserName|endswith: '$'
    condition: selection and not filter
level: critical
tags: [attack.credential_access, attack.t1003.006]
---
title: Cobalt Strike / Sliver / Havoc Named Pipe Pattern
id: 3e8f2a1b-4c5d-6e7f-8a9b-0c1d2e3f4a5b
status: experimental
logsource: { product: windows, category: pipe_created }
detection:
    selection:
        PipeName|re: '\\(MSSE-|msagent_|postex_\d|status_\w+|mojo\.\d+\.\d+\.\d+|sliver-|interactsh)'
    condition: selection
level: high
tags: [attack.command_and_control, attack.t1071, attack.t1559]
---
title: Service Created With Suspicious Binary Path (Lateral / Persistence)
id: 9d0e1f2a-3b4c-5d6e-7f80-91a2b3c4d5e6
status: stable
logsource: { product: windows, service: system }
detection:
    selection:
        EventID: 7045
    filter:
        ServiceFileName|contains:
            - 'C:\Windows\'
            - 'C:\Program Files\'
    condition: selection and not filter
level: medium
tags: [attack.persistence, attack.lateral_movement, attack.t1543.003, attack.t1021.002]
```

## Toolchain: pySigma / sigma-cli compile and lint

```bash
# Install (2025 stack)
pip install sigma-cli \
    pysigma-backend-splunk \
    pysigma-backend-elasticsearch \
    pysigma-backend-microsoft365defender \
    pysigma-pipeline-sysmon

# Validate (schema, unique IDs, required fields) - run in CI
sigma check rules/

# Compile one rule to Splunk, applying the Sysmon field-mapping pipeline
sigma convert -t splunk -p sysmon rules/powershell_encoded_download.yml

# Compile a directory to Microsoft 365 Defender (KQL) and to Elastic ES|QL
sigma convert -t microsoft365defender rules/ -o out_mde.kql
sigma convert -t elasticsearch --format esql rules/ -o out_esql.txt
```

`scripts/dac_validate.py` wraps `sigma check` + `sigma convert`, additionally enforcing
unique UUIDs and mandatory `tags:` ATT&CK references, and exits non-zero on any failure so
it gates a CI merge. `scripts/sigma_pipeline.sh` drives the full lint → convert →
deploy-artifact flow for multiple backends.

## EVTX triage at scale: Hayabusa / Chainsaw / Velociraptor native Sigma

For DFIR and offline hunting you run Sigma directly against `.evtx`:

```bash
# Hayabusa (Yamato-Security) - fast Sigma timeline over a logs directory
hayabusa csv-timeline -d ./EVTX_logs -o timeline.csv -p super-verbose
hayabusa csv-timeline -f Security.evtx -o sec.csv --enable-all-rules
# v2.18.0+ Live Response package: XOR-encoded rules + single binary, minimizes disk writes
#   and avoids AV; ideal for endpoint triage without disturbing the USN journal.

# Chainsaw (WithSecure) - hunt with Sigma + bundled mapping
chainsaw hunt ./EVTX_logs -s sigma/ --mapping sigma-event-logs-all.yml --csv --output cs/
```

**Velociraptor 0.74+ (Feb 2025) native Sigma engine** replaced shelling out to Hayabusa:
~5x faster matching and ~200-300MB RAM vs Hayabusa's 1-2GB, so it is safe to deploy
fleet-wide. It introduced **Sigma Models** (preset log-source collections) and a GUI Sigma
Editor.

```sql
-- Velociraptor VQL: offline EVTX triage with the built-in sigma() engine
-- Uses the Windows.Sigma.Base model (maps Sigma fields -> EventData.* in EVTX)
SELECT * FROM sigma(
   rules=read_file(filename="rules/*.yml"),
   log_sources= server_metadata().Sigma,    -- Windows.Sigma.Base field mappings
   default_details="."
) WHERE Sigma.level =~ "high|critical"

-- Live real-time matching following the event log:
SELECT * FROM watch_evtx(filename="C:/Windows/System32/winevt/Logs/*.evtx")
```

Field-mapping is the gotcha: a Sigma `Path` field must map to `EventData.Path` (or the
backend's normalized column). Velociraptor's `Windows.Sigma.Base` model and the
`sigma-event-logs-all.yml` mapping handle this; for a custom SIEM you maintain a pipeline.

## AI-assisted authoring (2025) — use, but verify

Tools like **SigmaGen** (fine-tuned LLM, ingests CTI to emit ATT&CK-mapped Sigma; APAC
ATT&CK Workshop 2025) and **Uncoder AI** (auto-predicts ATT&CK tags from 20k+ detections)
speed authoring. Treat generated rules as drafts: every one must pass `sigma check`, get a
real unique UUID, be validated against an Atomic Red Team test, and have FPs triaged before
it leaves `status: experimental`.

## Detection (of evasion targeting the rules themselves)

- Attackers profile your rules. Keep `status: experimental` rules out of public repos that
  an operator could read; rotate high-value detections.
- Watch for log clears (`Security` 1102), audit-policy tampering (`auditpol /clear`,
  EID 4719), and WEF subscription removal — these blind the very pipeline Sigma runs on.

## OPSEC (analyst)

- Test new rules in a lab or against historical data before production to measure FP rate.
- Version-control rules; treat a noisy rule as a bug and fix or demote it rather than
  letting the SOC mute the whole feed.

## References

- SigmaHQ rule repo + Sigma Correlation spec (sigmahq.io).
- "Threat Detection and Incident Response with MITRE ATT&CK and Sigma Rules" — Graylog, 2025.
- "SigmaGen: AI-Powered ATT&CK-Mapped Threat Detection with Sigma Rules" — Night-Wolf / MITRE CTID APAC 2025.
- "Uncoder AI Automates MITRE ATT&CK Tagging in Sigma Rules" — SOC Prime, 2025.
- Yamato-Security Hayabusa (github.com/Yamato-Security/hayabusa); WithSecure Chainsaw.
- "Velociraptor 0.74 Release" + "Developing Sigma Rules in Velociraptor" — Velocidex docs, Feb 2025.
- mdecrevoisier/SIGMA-detection-rules (350+ correlation rules mapped to ATT&CK).
