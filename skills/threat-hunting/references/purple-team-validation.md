# Purple-Team Validation — Atomic Red Team, Caldera, Coverage & Gap Analysis

## Theory / Mechanism

A detection you never tested is a hypothesis, not a control. Purple teaming closes the loop:
**detection = code, adversary behavior = test cases, coverage gaps = bugs.** You emulate a
specific ATT&CK technique, confirm the expected telemetry fires and the rule alerts, and
treat any miss as a fixable defect. Repeating this continuously (per release / weekly)
turns Atomic Red Team into a regression-test suite for the SOC. This is the validation half
of the Detection-as-Code pipeline in `methodology-hunt-loop.md`.

The 2025 **Purple Team Exercise Framework v4 (PTEFv4)** formalized this with a
Detection-as-Code expansion, **ATT&CK v18 Detection-Strategies/Analytics alignment**,
continuous purple teaming with automated regression testing + BAS integration, and a broader
tool set (SCYTHE, MITRE Caldera, Atomic Red Team, C2 Matrix).

## Atomic Red Team — technique-scoped unit tests

Each "atomic" maps to one ATT&CK technique, is self-contained (a few commands), and runs in
< 5 minutes — ideal for CI and daily validation. Drivers: `Invoke-Atomic` (PowerShell) and
`atomic-operator` (Python) for scripting into pipelines.

```powershell
# Install the execution framework (lab/VM only)
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics

# T1003.001 - LSASS dump. Validate Sysmon EID 10 + your LSASS-access Sigma fires.
Invoke-AtomicTest T1003.001 -TestNumbers 1,2,3 -CheckPrereqs
Invoke-AtomicTest T1003.001 -TestNumbers 1,2,3
Invoke-AtomicTest T1003.001 -Cleanup            # ALWAYS clean up

# T1059.001 - PowerShell. Validate ScriptBlock (4104) + encoded-cmd Sigma fires.
Invoke-AtomicTest T1059.001 -TestNumbers 1

# T1053.005 - Scheduled task persistence. Validate EID 4698 + your persistence rule.
Invoke-AtomicTest T1053.005 -TestNumbers 1
Invoke-AtomicTest T1053.005 -Cleanup
```

```bash
# Python driver for CI (atomic-operator) - run a technique, then assert detection
pip install atomic-operator
atomic-operator run --technique T1218.011 --test-guids <guid> \
    --atomics-path ./atomic-red-team/atomics
```

Validation pattern for each atomic:
1. Snapshot the lab VM; run `-CheckPrereqs`.
2. Execute the atomic.
3. Query the SIEM/EVTX for the expected telemetry **and** the expected rule alert.
4. Record PASS (telemetry + alert), PARTIAL (telemetry, no alert → rule gap), or FAIL
   (no telemetry → visibility gap).
5. `-Cleanup` and revert.

## MITRE Caldera — chained, autonomous emulation

For multi-step adversary emulation (not single atomics), **Caldera** runs operations from
adversary profiles built of abilities (each tagged with an ATT&CK technique). Use it to test
*correlation* rules and full kill-chains rather than isolated events.

```bash
# Caldera server (lab)
git clone https://github.com/mitre/caldera.git --recursive && cd caldera
python3 server.py --insecure
# Deploy a Sandcat agent on the target VM, then run an adversary profile (e.g. "Discovery")
# Validate: do your AD-recon burst (KQL) and lateral-movement (7045) detections chain-fire?
```

## Coverage & gap analysis (ATT&CK v18-aware)

Map every detection to ATT&CK and find the holes. `scripts/coverage_matrix.py` ingests your
Sigma rules (reads `tags:` for `attack.tXXXX`) plus an optional atomic-test results file and
emits:

- a **coverage matrix** (technique × {Sysmon, EDR, SIEM rule, Network} × status),
- a **MITRE ATT&CK Navigator** layer JSON for visual heatmapping,
- a prioritized **gap list** (no detection + high adversary use = critical gap).

```bash
# Build coverage layer from your rule repo + atomic results
python3 scripts/coverage_matrix.py \
    --rules rules/ \
    --atomic-results atomic_results.json \
    --navigator-out attack_layer.json \
    --gaps-out gaps.csv
# Import attack_layer.json at https://mitre-attack.github.io/attack-navigator/
```

Example matrix (the kind `coverage_matrix.py` renders):

```
| ATT&CK             | Sysmon  | EDR     | SIEM Rule | Network | Status   |
|--------------------|---------|---------|-----------|---------|----------|
| T1003.001 LSASS    | EID 10  | Yes     | Sigma     | -       | COVERED  |
| T1059.001 PS       | EID 1   | Yes     | Sigma     | -       | COVERED  |
| T1021.002 SMB      | EID 3   | Yes     | Sigma     | Zeek    | COVERED  |
| T1071.001 HTTPS C2 | -       | Partial | -         | JA4     | PARTIAL  |
| T1528 OAuth token  | -       | -       | KQL       | -       | COVERED  |
| T1550.001 PRT      | EID 10  | Partial | KQL       | -       | PARTIAL  |
| T1562.001 ETW/AMSI | EID 25  | Partial | Sigma     | -       | PARTIAL  |
| T1134.001 Token    | -       | Partial | -         | -       | GAP      |
```

Prioritize gaps by adversary prevalence: cross-reference the technique against current CTI
(e.g., device-code/OAuth `T1528` and ETW-patch `T1562.001` are heavily used in 2025-2026,
so a gap there outranks a rarely-seen technique).

## Detection-quality regression (don't trade FPs for coverage)

Each new rule must be validated *and* measured for false positives on baseline traffic
before promotion from `experimental` → `stable`. Track per-rule: TP (atomic fired it), FP
rate on a clean week, and ATT&CK mapping. A rule that fires on the atomic but floods on
benign data is a failed test, not a success.

## OPSEC / safety

- **Run atomics and Caldera only in an isolated, snapshotted lab or an explicitly authorized
  range** — many atomics genuinely dump credentials, create persistence, or disable
  defenses. Always `-Cleanup` / revert.
- Whitelist the test source host in any auto-response/SOAR so emulation does not trigger live
  containment of a production asset.
- Log the engagement: technique, time, operator, expected vs. observed detection — this is
  the evidence trail that feeds the report and the coverage matrix.

## References

- Red Canary Atomic Red Team (github.com/redcanaryco/atomic-red-team); Invoke-AtomicRedTeam; atomic-operator.
- MITRE Caldera (github.com/mitre/caldera).
- SCYTHE Purple Team Exercise Framework v4 (github.com/scythe-io/purple-team-exercise-framework), 2025.
- "Building a Purple Team Detection Lab: From Adversary Emulation to Verified Detections" — Malvik Security, 2025.
- "How to Use Atomic Red Team for MITRE ATT&CK-Based Threat Testing" — GoCodeo, 2025.
- MITRE ATT&CK Navigator (mitre-attack.github.io/attack-navigator).
