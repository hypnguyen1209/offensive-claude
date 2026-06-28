# Agent Red-Team Tooling, Methodology & Mapping

## Theory / Mechanism

A repeatable agent red-team needs three things beyond payloads: (1) **coverage** mapped to a
recognized taxonomy so findings are comparable and the assessment is defensible; (2) a **harness**
that runs attacks, scores attack-response pairs, and emits **Attack Success Rate (ASR)**; (3)
**finding records** with severity/CWE/CVSS/ATT&CK so they slot into the engagement report. The
2024-2026 shift is from single-shot probing to **agent-orchestrated, multi-turn** campaigns —
an AI picks attacks, composes transforms, runs them, and produces structured findings.

### Taxonomies to map against
- **OWASP Top 10 for LLM Applications 2025** — LLM01 Prompt Injection … LLM05 Improper Output
  Handling, LLM06 Excessive Agency, etc.
- **OWASP Top 10 for Agentic Applications (ASI01–ASI10, Dec 2025)** — ASI01 Goal Hijack,
  ASI02 Tool Misuse, ASI03 Identity/Privilege Abuse, ASI04 Supply Chain, ASI05 Unexpected Code
  Execution, ASI06 Memory/Context Poisoning, ASI07 Insecure Inter-Agent Comms, ASI08 Cascading
  Failures, ASI09 Human-Agent Trust Exploitation, ASI10 Rogue Agents.
- **MITRE ATLAS** (Oct 2025: 15 tactics / 66 techniques / 46 sub-techniques; +14 agentic
  techniques with Zenity Labs) — e.g. AML.T0051 (LLM Prompt Injection), AML.T0054 (LLM Jailbreak),
  AML.T0070 (RAG poisoning-class), AML.T0071 (red-teaming eval).
- **NIST AI RMF** measure functions for compliance reporting.

## Modern 2024-2026 Tooling (verified)

| Tool | Owner | Strength | Agentic relevance |
|------|-------|----------|-------------------|
| **PyRIT** | Microsoft AI Red Team | Depth: multi-turn orchestrators (Crescendo, TAP, Skeleton Key, XPIA), multi-modal converters, scorers | Simulates memory poisoning / tool misuse / role escalation via prompting (CSA: orchestration + scoring, but **does not execute real agents**). Repo moved Azure/PyRIT → **microsoft/PyRIT** (Azure repo archived Mar 2026). |
| **Garak** | NVIDIA | Breadth: 19+ probe families (encoding, GCG suffixes, package-hallucination, XSS, prompt-injection) | v0.14.0 adds agentic support; plugin probes; engine inside NeMo Evaluator. |
| **Promptfoo** | Promptfoo | Config-driven YAML; framework **presets** `owasp:llm`, `owasp:agentic`, `nist:ai:measure`, `mitre:atlas`; auto-grading | `owasp:agentic` preset maps scans to ASI01–ASI10; Hydra multi-turn strategy. |
| **DeepTeam** | open source | OWASP-Agentic-oriented red-team framework | ASI coverage. |
| **AI Red Teaming Agent** | Microsoft Foundry | Managed PyRIT: scan → score ASR → scorecard | Azure-native agent assessment. |

**Layered methodology (combine the tools):**
```
L1 Broad scan      (30–60m)  Garak / Promptfoo full probe suites — baseline, run nightly/per-release
L2 Compliance scan (15–30m)  Promptfoo owasp:agentic preset — ASI01–ASI10, run per-PR/weekly
L3 Deep exploit    (2–4h)    PyRIT Crescendo/TAP/custom converters — run bi-weekly/security sprints
L4 Expert manual   (1–2d)    business-logic, social-engineering chains, novel vectors — quarterly
```
Manual testing stays essential (Microsoft: complete manual red teaming before automating).

## Complete working code/commands

`scripts/agent_redteam_harness.py` ties the engagement together: `enumerate` the agent surface,
`run` a campaign (driving the per-technique scripts in this skill), `score` ASR, and `report`
finding records (`templates/exploit/findings/` schema) tagged with OWASP/ASI/ATLAS/CWE/CVSS.

```bash
pip install requests pyyaml

# Enumerate exposed tools / MCP servers / memory store / data channels
python scripts/agent_redteam_harness.py enumerate --endpoint $AGENT_URL --auth-bearer "$TK" --out surface.json

# Run a campaign defined in YAML (selects techniques + scripts + scope), emit findings
python scripts/agent_redteam_harness.py run --config harness.yaml --report findings/

# Score a transcript directory into an ASR table + per-ASI scorecard
python scripts/agent_redteam_harness.py score --transcripts out/ --scorecard scorecard.json
```

Minimal `harness.yaml`:
```yaml
target:
  endpoint: https://target.example/agent/chat
  auth_bearer_env: TARGET_TOKEN
scope:
  allow_destructive: false
  oast_base: https://x8f2.oast.pro
campaign:
  - technique: indirect_prompt_injection   # -> indirect_injection_forge.py
    asi: ASI01
    atlas: AML.T0051.001
  - technique: memory_poisoning            # -> memory_poison_minja.py
    asi: ASI06
    atlas: AML.T0070
  - technique: excessive_agency            # -> agency_tool_fuzzer.py
    asi: ASI02
    atlas: AML.T0053
  - technique: multiturn_jailbreak         # -> multiturn_jailbreak.py
    asi: ASI01
    atlas: AML.T0054
    strategy: crescendo
    max_turns: 8
report:
  template: templates/exploit/findings/finding.md
```

Equivalent vendor-tool invocations:
```bash
# Promptfoo: OWASP Agentic compliance scan -> ASI01..ASI10 scorecard
promptfoo redteam init --purpose "support agent with tools" && \
promptfoo redteam run --plugins owasp:agentic --output report.html

# Garak: broad probe sweep
python -m garak --model_type rest --generator_option_file target.json \
  --probes promptinject,encoding,xss,packagehallucination

# PyRIT: Crescendo orchestrator (Python) — see multiturn_jailbreak.md for the loop semantics
# from pyrit.orchestrator import CrescendoOrchestrator
```

## Detection

This cluster is the *defender-equivalent* of the others — its detections aggregate theirs:
```yaml
title: Coordinated AI Agent Red-Team Activity
id: a3c1e7d2-aiagent-harness-0006
status: experimental
logsource:
  product: llm_gateway
  service: chat
detection:
  known_tooling_ua:
    user_agent|contains: ['garak','promptfoo','pyrit']
  probe_burst:
    selection: distinct_attack_categories_per_hour > 5
  scorer_traffic:
    selection: paired_attacker_judge_calls == true
  condition: known_tooling_ua or (probe_burst and scorer_traffic)
level: medium
```
- Detect by **default User-Agents** of Garak/Promptfoo/PyRIT (red teams should rotate these; blue
  teams should baseline them), and by the structural signature of attacker→judge paired traffic.
- Build a **scorecard over time**: track ASR per ASI category release-over-release; a rising ASR is
  a regression. Map every finding to ASI + ATLAS so trends are comparable.
- IOCs: tool-default UAs, bursts spanning many distinct attack categories, evaluation/judge calls
  interleaved with target calls.

## OPSEC

- **Touches:** the target endpoint (high request volume), your own attacker/judge LLM accounts, and
  local result/transcript stores (may contain elicited sensitive output — treat as evidence).
- **Cleanup:** archive transcripts + scorecards as report artifacts; purge any sensitive content
  elicited during testing per the ROE; remove planted RAG/memory/MCP artifacts created by the
  sub-technique scripts (their own references list specifics).
- **Evasion considerations:** rotate User-Agents and source IPs (default `garak`/`promptfoo`/
  `pyrit` UAs are trivially fingerprinted); spread campaigns over time to avoid category-burst
  detection; segregate per-tenant tokens so one client's traffic never leaks to another. Pin and
  record model + guardrail versions so ASR numbers are reproducible and defensible.

## References
- Microsoft PyRIT — github.com/microsoft/PyRIT (Azure/PyRIT archived Mar 2026); AI Red Teaming Agent, Microsoft Foundry.
- NVIDIA Garak — github.com/NVIDIA/garak (v0.14.0 agentic support); inside NeMo Evaluator.
- Promptfoo red-team — promptfoo.dev/docs/red-team (presets owasp:llm, owasp:agentic, mitre:atlas).
- OWASP Gen AI Security Project — Top 10 for LLM Apps 2025; Top 10 for Agentic Applications (ASI01–ASI10, Dec 2025); Gen AI Red Teaming Guide (Jan 2025).
- MITRE ATLAS (Oct 2025) — atlas.mitre.org. CSA, "Evaluating PyRIT for Agentic AI Red Teaming."
- NIST AI Risk Management Framework.
