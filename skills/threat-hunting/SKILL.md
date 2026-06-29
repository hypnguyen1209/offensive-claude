---
name: threat-hunting
description: Use when hunting threats or engineering detections — ATT&CK Detection-Strategies, Sigma + correlation with Detection-as-Code CI, Windows endpoint hunting (Sysmon/ETW/LSASS/LOLBins), network C2 hunting (JA4+, beaconing, DNS tunneling), cloud-identity hunting, Atomic Red Team purple-team validation
metadata:
  type: defensive
  phase: detection
  tools: sigma-cli, pysigma, hayabusa, chainsaw, velociraptor, sysmon, zeek, rita, ja4, atomic-red-team, caldera, splunk, sentinel, defender, kql
  mitre: TA0043
kill_chain:
  phase: [report]
  step: [8]
  attck_tactics: [TA0043, TA0042, TA0011, TA0006, TA0005]
  attck_techniques: [T1059.001, T1003.001, T1562.001, T1562.002, T1218, T1105, T1071, T1071.001, T1071.004, T1571, T1572, T1528, T1550.001, T1078.004, T1098, T1543.003, T1070.001, T1558.003, T1003.006]
depends_on: [red-team-ops, incident-response]
feeds_into: []
inputs: [finding_records, log_data, ioc_list, evtx, zeek_logs, cloudtrail, sigin_logs]
outputs: [sigma_rules, correlation_rules, attck_navigator_export, coverage_matrix, detection_report, hunt_findings]
references:
  - references/methodology-hunt-loop.md
  - references/windows-endpoint-hunting.md
  - references/sigma-rule-engineering.md
  - references/network-c2-hunting.md
  - references/cloud-identity-hunting.md
  - references/purple-team-validation.md
scripts:
  - scripts/dac_validate.py
  - scripts/evtx_hunt.py
  - scripts/beacon_hunter.py
  - scripts/cloudtrail_hunt.py
  - scripts/coverage_matrix.py
  - scripts/entra_hunt.kql
  - scripts/sigma_pipeline.sh
  - scripts/sysmon_config_2025.xml
---

# Threat Hunting & Detection Engineering

## When to Activate

- Hypothesis-driven hunting across endpoint, network, cloud, and identity telemetry
- Writing & shipping detections (Sigma + correlation) as version-controlled code in CI
- Mapping & measuring coverage against MITRE ATT&CK v18 (Detection Strategies / Analytics)
- Hunting Windows post-exploitation: ETW/AMSI tampering, LSASS dumping, LOLBins, injection
- Hunting C2 in encrypted traffic: JA4+/JA4X fingerprints, beaconing, DNS tunneling
- Hunting cloud-identity attacks: Entra device-code/OAuth phishing, PRT theft, CloudTrail abuse
- Purple-team validation: emulate ATT&CK with Atomic Red Team/Caldera, find detection gaps
- Triaging EVTX/Zeek/CloudTrail offline during IR without a SIEM

## Technique Map

| Technique | ATT&CK | CWE | Reference | Script |
|-----------|--------|-----|-----------|--------|
| Hypothesis-driven hunt loop (PEAK/TaHiTI) | TA0043 | CWE-778 | references/methodology-hunt-loop.md | - |
| ATT&CK v18 Detection-Strategies / Analytics mapping | TA0043 | CWE-778 | references/methodology-hunt-loop.md | scripts/coverage_matrix.py |
| Detection-as-Code CI (lint + compile) | TA0043 | CWE-778 | references/methodology-hunt-loop.md | scripts/dac_validate.py |
| Sysmon 15 PPL + tamper/visibility-gap | T1562.001 | CWE-693 | references/windows-endpoint-hunting.md | scripts/sysmon_config_2025.xml |
| ETW / AMSI in-memory patch detection | T1562.001, T1562.002 | CWE-693 | references/windows-endpoint-hunting.md | scripts/evtx_hunt.py |
| LSASS credential-access handle hunt | T1003.001 | CWE-522 | references/windows-endpoint-hunting.md | scripts/evtx_hunt.py |
| LOLBin / process-tree anomaly hunt | T1218, T1105, T1059 | CWE-78 | references/windows-endpoint-hunting.md | scripts/evtx_hunt.py |
| Sigma rule + correlation engineering | TA0043 | CWE-778 | references/sigma-rule-engineering.md | scripts/dac_validate.py |
| EVTX triage (Hayabusa/Chainsaw/Velociraptor) | TA0043 | CWE-778 | references/sigma-rule-engineering.md | scripts/sigma_pipeline.sh |
| JA4+/JA4X C2 fingerprinting | T1071.001 | CWE-300 | references/network-c2-hunting.md | scripts/beacon_hunter.py |
| Beaconing / long-conn / prevalence (RITA-style) | T1071, T1571 | CWE-940 | references/network-c2-hunting.md | scripts/beacon_hunter.py |
| DNS tunneling / DGA / DoH abuse | T1071.004, T1572 | CWE-940 | references/network-c2-hunting.md | scripts/beacon_hunter.py |
| Entra device-code / OAuth consent phishing | T1528, T1566 | CWE-287 | references/cloud-identity-hunting.md | scripts/entra_hunt.kql |
| PRT theft / token replay | T1550.001 | CWE-522 | references/cloud-identity-hunting.md | scripts/entra_hunt.kql |
| AWS CloudTrail abuse / log tampering | T1078.004, T1098, T1562.008 | CWE-269 | references/cloud-identity-hunting.md | scripts/cloudtrail_hunt.py |
| Atomic Red Team / Caldera validation | TA0043 | CWE-778 | references/purple-team-validation.md | scripts/coverage_matrix.py |
| Coverage matrix + ATT&CK Navigator + gap report | TA0043 | CWE-778 | references/purple-team-validation.md | scripts/coverage_matrix.py |

## Quick Start

```bash
# 0. Deploy hunting telemetry baseline (Sysmon 15+, PPL self-protected)
sysmon -accepteula -i scripts/sysmon_config_2025.xml      # or: sysmon -c <file> to update

# 1. Offline endpoint triage over collected EVTX (no SIEM)
python3 scripts/evtx_hunt.py /cases/host01/EVTX --min-severity medium --json host01.json

# 2. Network: hunt C2 beacons / DNS tunneling over Zeek logs (+ optional JA4 blocklist)
zeek -r capture.pcap LogAscii::use_json=T
python3 scripts/beacon_hunter.py --conn conn.log --dns dns.log \
        --ja4-blocklist bad_ja4.txt --min-score 0.7

# 3. Cloud/identity: paste scripts/entra_hunt.kql into Sentinel/Defender;
#    triage AWS offline:
python3 scripts/cloudtrail_hunt.py /cases/cloudtrail/ --json ct_findings.json

# 4. Detection-as-Code: lint + compile your Sigma repo for CI (fail-fast)
python3 scripts/dac_validate.py rules/ --backend splunk --pipeline sysmon --fail-on-error
./scripts/sigma_pipeline.sh rules/ build/ splunk microsoft365defender elasticsearch

# 5. Purple-team validate + measure coverage (ATT&CK v18 Navigator layer + gaps)
Invoke-AtomicTest T1003.001 -TestNumbers 1,2,3   # lab only; -Cleanup after
python3 scripts/coverage_matrix.py --rules rules/ --atomic-results atomic_results.json \
        --watchlist watchlist.txt --navigator-out attack_layer.json --gaps-out gaps.csv
```

## OPSEC & Detection (summary)

| Technique | Telemetry / IOC | Detection (Sigma / EDR) | OPSEC note |
|-----------|-----------------|--------------------------|------------|
| ETW/AMSI patch | RWX in ntdll/amsi; ScriptBlock w/ AmsiScanBuffer+VirtualProtect | Sigma AMSI/ETW patch rule; Sysmon EID 25; ETW-TI (kernel) | Userland patch defeats single source — correlate EID25 + ETW-TI + behavior |
| Sysmon kill | System 7036/7034, SysmonDrv unload, EPS drop to 0 | Visibility-gap metric on chatty hosts | Sysmon 15 is PPL; attacker kills agent instead — alert on stop/unload |
| LSASS dump | EID 10 handle to lsass + `.dmp` write | LSASS-access Sigma; access-mask + non-system source | Baseline your own EDR/AV SourceImage set first or you flood the SOC |
| LOLBin abuse | certutil/mshta/regsvr32 + http/decode/scrobj | LOLBin Sigma; parent→child tree anomalies | Hunt cold data first; live triage tips an EDR-aware operator |
| Beaconing | periodic intervals, uniform sizes, low prevalence | beacon_hunter.py CV<0.3; RITA; long-conn on non-interactive port | Need days of logs — small PCAPs inflate FPs |
| JA4X C2 | randomized certs sharing one JA4X (Sliver/Havoc) | JA4 segment-pivot; JA4X blocklist at TLS-terminating proxy | TLS 1.3 encrypts certs — capture at egress/proxy, don't block on FP alone |
| DNS tunneling | long/high-entropy subdomains, TXT volume, NXDOMAIN spikes | DNS entropy/volume scoring; DoH-to-public Sigma | Baseline normal long-FQDN apps (CDNs) before alerting |
| Device-code phish | `deviceCode` sign-in, broker/OfficeHome AppId, new ASN | entra_hunt.kql #1+#2; Elastic open rules | Baseline sanctioned device-code apps; not every device-code is evil |
| PRT theft | `primaryRefreshToken` from multi-geo same day | PRT KQL + LSASS/cloudAP endpoint join | Control-plane is the ONLY evidence — retain logs ≥90d before you need them |
| CloudTrail abuse | StopLogging/DeleteTrail, CreateAccessKey for others, Describe* burst | cloudtrail_hunt.py; Athena tamper query | Attackers disable logging early; enable org-wide all-region trail up front |

## Deep Dives

- **references/methodology-hunt-loop.md** — PEAK/TaHiTI hunt loop, ATT&CK v18 Detection Strategies (`DETxxxx`) & Analytics (`ANxxxx`) replacing legacy data sources, Detection-as-Code CI/CD (PTEFv4), visibility-gap detection.
- **references/windows-endpoint-hunting.md** — Sysmon 15 PPL & tamper detection, ETW/AMSI in-memory patch detection (ETW-TI, EID 25, ScriptBlock), LSASS handle hunting, LOLBins & process-tree anomalies.
- **references/sigma-rule-engineering.md** — Sigma rule anatomy, correlation rules (value_count/temporal), pySigma/sigma-cli compile, Hayabusa/Chainsaw/Velociraptor 0.74 native-Sigma EVTX triage, AI-assisted authoring (SigmaGen/Uncoder).
- **references/network-c2-hunting.md** — JA4+/JA4S/JA4H/JA4X fingerprinting, Sliver/Havoc shared JA4X, RITA-style beaconing & long-connection stats, DNS tunneling/DGA/DoH, C2 framework signature cheat-sheet.
- **references/cloud-identity-hunting.md** — Entra device-code phishing (STORM-2372, Tycoon2FA, EvilTokens), OAuth consent abuse, PRT theft, Graph enumeration, AWS CloudTrail abuse & tampering.
- **references/purple-team-validation.md** — Atomic Red Team unit tests, MITRE Caldera chained emulation, ATT&CK v18-aware coverage matrix, Navigator layer generation, prioritized gap analysis.
