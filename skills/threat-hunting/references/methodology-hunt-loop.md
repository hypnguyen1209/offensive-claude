# Hunt Methodology, ATT&CK v18 & Detection-as-Code

## Theory / Mechanism

Threat hunting is a *hypothesis-driven*, analyst-led search for adversary activity that
existing alerts missed. It is the inverse of alerting: you assume compromise, form a
testable hypothesis grounded in adversary TTPs, and pivot through telemetry to confirm or
refute it. Detection engineering then converts confirmed hunt findings into durable,
version-controlled detections.

The two disciplines form a loop:

```
Threat Intel / Red-team finding
        │
        ▼
  Hypothesis  ──►  Hunt (pivot telemetry)  ──►  Finding?
        ▲                                          │ yes
        │                                          ▼
  Tune / re-run ◄── CI/CD validate ◄── Codify as Sigma + map ATT&CK
```

### The PEAK / TaHiTI hunt loop (operational structure)

1. **Prepare** — pick the hypothesis. Sources: a new CVE/exploit, an internal red-team
   report (your `findings/` records), a CTI report on an active campaign, or an
   anomaly observed in a baseline.
2. **Execute** — translate the hypothesis into queries against the right data source
   (ATT&CK *Log Sources*), pivot, and triage candidates.
3. **Act / Knowledge** — document, escalate true positives to IR, and feed the result back
   as a detection (codify) and/or an updated baseline.

A well-formed hypothesis is **falsifiable and scoped to telemetry you actually have**:
> "If an operator used the `STORM-2372` device-code technique, then Entra sign-in logs
> will show `authenticationProtocol == deviceCode` from a never-before-seen ASN, followed
> within 1h by Graph mailbox enumeration from the same session ID."

## MITRE ATT&CK v18 — Detection Strategies & Analytics (Oct 28, 2025)

ATT&CK v18 (released **2025-10-28**, following v17 in April 2025) replaced the old free-text
"Detection" notes and legacy *Data Sources* with a structured, behavior-first model. This is
the most important change for hunters to understand because it changes how you map coverage.

| Old model (≤ v17) | New model (v18+) |
|-------------------|------------------|
| One-sentence "Detection:" text per technique | **Detection Strategy** objects (`DETxxxx`) — high-level approach |
| Data Sources (e.g. "Process: Process Creation") | **Analytics** objects (`ANxxxx`) — platform-specific detection logic |
| Static, hard to operationalize | **Log Sources** + Data Components — what telemetry to collect |

- **Detection Strategy (`DETxxxx`)** = *what behavior* to look for (e.g. `DET0088`
  "Backup Software Discovery via CLI, Registry, and Process Inspection").
- **Analytic (`ANxxxx`)** = *how* to detect it on a specific platform; each Analytic points
  to the **Log Sources** and Data Components needed.
- Legacy data sources (Command Execution, Application Log, AD Object Modification, etc.) are
  **fully deprecated** — still present in archived versions but superseded by Log Sources.

v18 also added Enterprise techniques for **CI/CD pipelines, Kubernetes, and cloud
databases**, ransomware-preparation behaviors, and adversaries monitoring threat-intel
sources about their own campaigns. v19 (Apr 2026) splits Defense Evasion into **Stealth**
and **Defense Impairment** tactics — re-map any old `TA0005` coverage when you adopt it.

**Practical impact for this skill:** when you write the coverage matrix
(`scripts/coverage_matrix.py`) and tag Sigma rules, map to technique IDs *and* note the
relevant Detection Strategy where it sharpens the analytic. Pull the live mapping from the
STIX bundle so you are never hard-coding a stale catalog.

```bash
# Pull ATT&CK v18 Enterprise STIX and list Detection Strategies / Analytics
curl -sSL https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json \
  -o enterprise-attack.json
python3 - <<'PY'
import json
b = json.load(open("enterprise-attack.json"))
objs = b["objects"]
det = [o for o in objs if o.get("type")=="x-mitre-detection-strategy"]
an  = [o for o in objs if o.get("type")=="x-mitre-analytic"]
print(f"Detection Strategies: {len(det)}  Analytics: {len(an)}")
PY
```

## Detection-as-Code (DaC) pipeline

Treat detections as software: **detection = code, adversary behavior = test cases,
coverage gaps = bugs.** The 2025-era stack (formalized in Purple Team Exercise Framework
v4 / PTEFv4, which added a Detection-as-Code expansion and ATT&CK v18 alignment):

1. Author the rule once in **Sigma** (portable YAML).
2. Lint + validate in CI (`sigma check`, schema, unique IDs, required ATT&CK tags).
3. **Compile** to the SIEM backend (`sigma convert -t splunk|esql|microsoft365defender`).
4. **Regression-test** with **Atomic Red Team** in an isolated lab: run the atomic, confirm
   the rule fires; fail the build if telemetry is missing.
5. Deploy on merge; track coverage metrics against ATT&CK.

`scripts/dac_validate.py` implements steps 2-3 (lint + convert) and is CI-ready. See
`references/sigma-rule-engineering.md` for the rule authoring depth and
`references/purple-team-validation.md` for the Atomic Red Team regression layer.

### Example GitHub Actions stage (fail-fast on broken detections)

```yaml
# .github/workflows/detections.yml
name: detection-as-code
on: [pull_request]
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install sigma-cli pysigma-backend-splunk pysigma-backend-elasticsearch pyyaml
      - name: Lint + convert all Sigma rules
        run: python3 skills/threat-hunting/scripts/dac_validate.py rules/ --backend splunk --fail-on-error
```

## Detection — measuring the hunt program itself

You cannot hunt what you cannot see. Audit collection health as its own detection:

```yaml
title: Critical Log Source Stopped Reporting (Visibility Gap)
id: 6b1f2c9a-0e8d-4d2a-9a31-7c4d5e6f7a8b
status: experimental
description: A normally-chatty host stops emitting Sysmon/Security events - possible log tampering or agent kill
logsource:
    product: windows
    service: sysmon
detection:
    # Implemented as a SIEM scheduled metric, not a single-event rule:
    # alert if EventID count from a host that averaged >N/hr drops to 0 for >30m
    timeframe: 30m
    condition: selection
level: high
tags:
    - attack.t1562.001   # Impair Defenses: Disable or Modify Tools
    - attack.t1070       # Indicator Removal
```

IOCs of a hunt/visibility gap: Sysmon service stop (`System` 7036 / `7045` removal),
WEF subscription disabled, `wevtutil cl` log clears (Security 1102), sudden EPS drop.

## OPSEC (analyst tradecraft)

- **Do not tip the adversary.** Run hunts over historical/cold data first
  (last 30-90 days) before touching live hosts. If you must collect live triage, use a
  read-only, signed agent and stage queries to avoid spiking host CPU (which an
  EDR-aware operator may notice).
- **Provenance.** Record the hypothesis, query, time window, and data source for every
  hunt so a finding is reproducible and defensible in the report.
- **False-positive discipline.** After analyzing thousands of production alerts, most
  "critical" rules should be "medium" — alert fatigue kills a SOC faster than a missed
  detection. Tune thresholds; prefer correlation over single-event noise.

## References

- "What's New in MITRE ATT&CK v18: Detection Strategies and Analytics Unveiled" — Picus Security, 2025.
- "ATT&CK v18: Detection Strategies, More Adversary Insights" — MITRE ATT&CK (Medium), Oct 2025.
- "MITRE Unveils ATT&CK v18 With Updates to Detections, Mobile, ICS" — SecurityWeek, 2025.
- "What Comes After Detection Rules? Smarter Detection Strategies in ATT&CK" — Lex Crumpton, MITRE ATT&CK (Medium), 2025.
- SCYTHE Purple Team Exercise Framework (PTEFv4) — github.com/scythe-io/purple-team-exercise-framework.
- Trellix, "Threat Hunting and Detection Engineering: A Proactive Approach to Cyber Defense" whitepaper.
- "Building a Purple Team Detection Lab" — Malvik Security, 2025.
