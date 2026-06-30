---
name: incident-response
description: Use when responding to or forensically investigating an incident — triage acquisition (Velociraptor/KAPE), Volatility 3 memory forensics, Chainsaw/Hayabusa EVTX timelining, anti-forensics detection, cloud IR, ransomware/ESXi response
metadata:
  type: defensive
  phase: response
  tools: velociraptor, volatility3, chainsaw, hayabusa, plaso, timesketch, uac, MFTECmd, EvtxECmd, dissect, certutil, awscli, az, gcloud
  mitre: TA0005
kill_chain:
  phase: [report]
  step: [8]
  attck_tactics: [TA0005, TA0007, TA0040, TA0010]
  attck_techniques: [T1070, T1070.001, T1070.004, T1070.006, T1562.001, T1070.008, T1055, T1014, T1003.001, T1486, T1490, T1485, T1078.004, T1552.005, T1528, T1219]
depends_on: [red-team-ops, threat-hunting]
feeds_into: [threat-hunting, malware-analysis]
inputs: [memory_dumps, disk_images, triage_packages, log_data, cloud_audit_logs]
outputs: [timeline, ioc_list, forensic_report, containment_actions, root_cause]
references:
  - references/triage-collection.md
  - references/memory-forensics.md
  - references/windows-evtx-timeline.md
  - references/anti-forensics-detection.md
  - references/cloud-ir.md
  - references/ransomware-esxi-ir.md
  - references/repo-compromise-forensics.md
scripts:
  - scripts/triage_collector.py
  - scripts/vol3_triage.py
  - scripts/ebpf_rootkit_hunt.sh
  - scripts/evtx_hunt.sh
  - scripts/timestomp_detect.py
  - scripts/cloud_ir_collect.py
  - scripts/ransomware_triage.ps1
  - scripts/dangling_commit_finder.py
  - scripts/gharchive_recover.py
---

# Incident Response & Digital Forensics

## When to Activate

- Active security incident: triage, scoping, evidence acquisition, containment, eradication
- Memory forensics — process injection, rootkit (incl. eBPF), credential-theft, network artifacts
- Windows event-log / artifact timelining and super-timeline reconstruction
- Anti-forensics detection — timestomping, log clearing, secure deletion, VSS recovery
- Cloud incident response — AWS/Azure/GCP identity-plane attacks and forensic collection
- Ransomware / extortion response — hypervisor (ESXi) encryption, backup destruction, fast-dwell intrusions
- Verifying suspect DFIR tooling used as adversary persistence (Velociraptor CVE-2025-6264)
- Repository-compromise post-mortem — a poisoned public repo / force-pushed malicious commit / deleted PR (recover via dangling commits + GH Archive + Wayback + Events API; see `references/repo-compromise-forensics.md`)

## Technique Map

| Technique | ATT&CK | CWE | Reference | Script |
|-----------|--------|-----|-----------|--------|
| Order-of-volatility live triage (Velociraptor/KAPE/UAC/CatScale) | T1074 | CWE-778 | references/triage-collection.md | scripts/triage_collector.py |
| Offline collector build + RAM acquisition (winpmem/LiME/AVML) | T1074 | CWE-778 | references/triage-collection.md | scripts/triage_collector.py |
| Suspect-tooling verification (Velociraptor CVE-2025-6264) | T1219 | CWE-269 | references/triage-collection.md | scripts/triage_collector.py |
| Volatility 3 process/injection analysis (malfind, hollow) | T1055 | CWE-noinfo | references/memory-forensics.md | scripts/vol3_triage.py |
| Credential extraction from memory (LSASS, hives) | T1003.001 | CWE-522 | references/memory-forensics.md | scripts/vol3_triage.py |
| Kernel + eBPF rootkit detection (LinkPro, linux.ebpf) | T1014 | CWE-269 | references/memory-forensics.md | scripts/ebpf_rootkit_hunt.sh |
| EVTX Sigma hunting & fast timeline (Chainsaw/Hayabusa) | T1070.001 | CWE-778 | references/windows-evtx-timeline.md | scripts/evtx_hunt.sh |
| Super-timeline (plaso) + Timesketch correlation | T1070 | CWE-778 | references/windows-evtx-timeline.md | scripts/evtx_hunt.sh |
| Timestomping detection ($SI vs $FN, USN FILE_CREATE) | T1070.006 | CWE-noinfo | references/anti-forensics-detection.md | scripts/timestomp_detect.py |
| Log/journal clearing & VSS recovery | T1070.001, T1490 | CWE-778 | references/anti-forensics-detection.md | scripts/timestomp_detect.py |
| Cloud IR — IMDSv2/SSRF cred theft, CloudTrail/GuardDuty | T1552.005, T1078.004 | CWE-918 | references/cloud-ir.md | scripts/cloud_ir_collect.py |
| Entra ID / token theft, identity-plane containment | T1528, T1078.004 | CWE-287 | references/cloud-ir.md | scripts/cloud_ir_collect.py |
| Ransomware rapid triage (Windows/Linux) | T1486, T1490, T1485 | CWE-noinfo | references/ransomware-esxi-ir.md | scripts/ransomware_triage.ps1 |
| ESXi / hypervisor ransomware response (UNC3944) | T1486 | CWE-noinfo | references/ransomware-esxi-ir.md | scripts/ransomware_triage.ps1 |

## Quick Start

```bash
# 0. PRESERVE ORDER OF VOLATILITY — RAM before disk, never reboot a live host first.
#    Windows RAM:  winpmem_mini_x64.exe mem.raw        Linux RAM: AVML  ./avml mem.lime
# 1. Network-wide / endpoint triage (pick one):
python3 scripts/triage_collector.py --os auto --out /evidence --velociraptor-collector
#    Verify any Velociraptor already on-host is NOT adversary persistence (CVE-2025-6264):
python3 scripts/triage_collector.py --check-velociraptor   # flags <0.73.5 / unknown service

# 2. Memory forensics (Windows or Linux dump):
python3 scripts/vol3_triage.py -f /evidence/mem.raw --os windows --hunt-injection --dump-suspect
bash   scripts/ebpf_rootkit_hunt.sh   # Linux live/IR eBPF rootkit hunt (LinkPro-aware)

# 3. Windows event-log fast timeline + Sigma hunt:
bash scripts/evtx_hunt.sh -d /evidence/C/Windows/System32/winevt/Logs -o /evidence/timeline

# 4. Anti-forensics: timestomp / USN tamper detection from $MFT + $J:
python3 scripts/timestomp_detect.py --mft /evidence/mft.csv --usn /evidence/usn.csv

# 5. Cloud breach (identity-plane first):
python3 scripts/cloud_ir_collect.py aws --collect-cloudtrail --contain-key AKIA... --enforce-imdsv2

# 6. Ransomware on a Windows host (rapid scope, do BEFORE eradication):
powershell -ep bypass -File scripts/ransomware_triage.ps1 -OutDir C:\IR
```

## OPSEC & Detection (summary)

> IR is defensive; "OPSEC" below = handling rules that keep evidence admissible and avoid tipping off an adversary who may be monitoring (UNC3944 joins IR bridges in real time).

| Technique | Telemetry / IOC | Detection (Sigma / EDR) | OPSEC / evidence note |
|-----------|-----------------|--------------------------|------------------------|
| Live triage | New service/scheduled task for collector; large file writes to evidence path | Baseline expected DFIR tooling; alert on unsigned collectors | Collect RAM first; never write evidence to the suspect volume; hash everything |
| Velociraptor abuse | velociraptor.exe svc <0.73.5; MSI from Azure Blob; relaunch after isolation | Sigma: unexpected Velociraptor service install; CVE-2025-6264 UpdateConfig | Treat unexpected Velociraptor as persistence, not your tooling |
| Memory injection | RX/RWX private VAD not file-backed (malfind); reparented svchost | Vol3 malfind/hollowprocesses; EDR unbacked-exec | Document plugin+offset provenance; keep raw dump read-only |
| eBPF rootkit | bpf_override_return; getdents/sys_bpf hooks; XDP magic-packet (win=54321); /etc/ld.so.preload | linux.ebpf vs baseline; ss(netlink) vs /proc/net diff; YARA MAL_LinkPro_* | bpftool/ps/ss lie on host — acquire RAM out-of-band (hypervisor/LiME RO) |
| EVTX clearing | 1102 (Security cleared), 104 (System cleared), gaps in EventRecordID | Chainsaw/Hayabusa Sigma; alert on 1102/104 | Pull EVTX from VSS/disk image, not the tampered live log |
| Timestomp | $SI ≠ $FN create time; sub-second zeros; USN FILE_CREATE mismatch | timestomp_detect.py; MFTECmd Created0x10 vs Created0x30 | $FN is harder to forge — anchor truth to it + USN/$LogFile |
| Cloud cred theft | InstanceCredentialExfiltration.OutsideAWS; impossible-travel sign-in; CloudTrail StopLogging | GuardDuty findings; Sentinel KQL risky sign-ins | Snapshot+immutable-export BEFORE remediation; logs to a SIEM the attacker can't reach |
| Ransomware/ESXi | Mass file rename/ext change; vCenter/ESXi SSH on; bulk vim-cmd VM power-off | SIEM: high-volume VM power-off from one host; vpxuser anomalies | Image before decrypt attempts; preserve note + sample; assume comms compromised |

## Deep Dives

- **references/triage-collection.md** — Order of volatility, RAM acquisition (winpmem/AVML/LiME), Velociraptor 0.75 offline collectors & hunts, KAPE targets, UAC/CatScale for Unix/ESXi, suspect-tooling verification incl. Velociraptor CVE-2025-6264.
- **references/memory-forensics.md** — Volatility 3 symbol-table workflow, Windows injection/credential/rootkit plugins, Linux pslist/check_syscall/hidden_modules, eBPF rootkit detection (LinkPro, linux.ebpf, bpf_override_return), dump extraction.
- **references/windows-evtx-timeline.md** — Chainsaw v2 & Hayabusa v3 Sigma hunting, key Event IDs, EvtxECmd/Eric Zimmerman parsers, plaso super-timeline, Timesketch + Dissect/Acquire enterprise scaling.
- **references/anti-forensics-detection.md** — Timestomping ($SI/$FN + USN cross-validation), log/journal clearing (1102/104, $LogFile gaps), secure-deletion artifacts, VSS recovery, $MFT/$J/$LogFile QuadLink correlation.
- **references/cloud-ir.md** — NIST SP 800-61r3 / SP 800-201, AWS CloudTrail/GuardDuty/IMDSv2-SSRF, Azure Entra ID token theft & KQL, GCP audit logs, identity-plane containment, automated evidence preservation.
- **references/ransomware-esxi-ir.md** — Ransomware rapid triage & decision flow, Scattered Spider/UNC3944 ESXi LotL chain, backup destruction, cross-platform builders (LockBit 5.0/DragonForce), containment & negotiation hygiene.
- **references/repo-compromise-forensics.md** — poisoned public-repo post-mortem from four INDEPENDENT, attacker-uncontrollable sources: dangling/force-pushed commits (`dangling_commit_finder.py`, git fsck via `git_safe`), GH Archive + Wayback CDX + live Events API (`gharchive_recover.py`); hypothesis→verify-at-source (evidence_kit)→adversarial-check→report, attribution-with-confidence, BigQuery kept optional.
