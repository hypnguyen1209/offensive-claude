# Offensive Security Research Config for Claude Code

A spec-driven offensive security framework for Claude Code — structured engagement workflows based on the Cyber Kill Chain, 31 kill-chain skills (multi-file progressive-disclosure) plus a **discipline layer** (a SessionStart dispatcher + 5 process/discipline skills), 7 collaborative agents, and a shared 47-file vulnerability reference library. Inspired by [GitHub's spec-kit](https://github.com/github/spec-kit) and [obra/superpowers](https://github.com/obra/superpowers).

## Quick Setup

```bash
# Method 0: Install as a Claude Code plugin (recommended — auto-loads the skill dispatcher)
/plugin marketplace add hypnguyen1209/offensive-claude
/plugin install offensive-claude@offensive-claude-marketplace
```

Installing as a plugin registers a **SessionStart hook** that injects the
`using-offensive-claude` dispatcher into every conversation, so the skill-invocation discipline
(scope → finding → OPSEC) is active from the first message.

```bash
# Method 1: One-liner install (recommended)
curl -sL https://raw.githubusercontent.com/hypnguyen1209/offensive-claude/main/install.sh | bash
```

```bash
# Method 2: Clone + install script
git clone https://github.com/hypnguyen1209/offensive-claude.git ~/offensive-claude
cd ~/offensive-claude && bash install.sh
```

```bash
# Method 3: Manual copy
git clone https://github.com/hypnguyen1209/offensive-claude.git ~/offensive-claude
cp -r ~/offensive-claude/skills ~/.claude/skills
cp -r ~/offensive-claude/agents ~/.claude/agents
cp -r ~/offensive-claude/templates ~/.claude/templates
cp -r ~/offensive-claude/workflows ~/.claude/workflows
cp -r ~/offensive-claude/commands ~/.claude/commands
cp -r ~/offensive-claude/presets ~/.claude/presets
cp ~/offensive-claude/CLAUDE.md ~/.claude/CLAUDE.md
```

Skills and agents activate automatically — no additional configuration needed.

## Engagement Workflow

Engagements follow the **Cyber Kill Chain** as a structured 9-phase pipeline with quality gates:

```
Phase 0    Phase 1    Phase 2      Phase 3     Phase 4       Phase 5       Phase 6    Phase 7       Phase 8
SCOPE  →  RECON  →  WEAPONIZE →  DELIVERY →  EXPLOIT  →  INSTALLATION →   C2    →  ACTIONS ON →  REPORT
                                                                                    OBJECTIVES
```

### Quick Start — Web App Pentest

```
/engage.init web-app --client ACME
/engage.scope                           # Define targets, ROE, authorization
/engage.recon                           # Subdomain enum, port scan, tech fingerprint
/engage.weaponize                       # Select exploits, design payloads
/engage.exploit                         # Execute exploits, document findings
/engage.report                          # Generate technical report + executive summary
```

### Orchestration Commands

| Command | Phase | Action |
|---------|-------|--------|
| `/engage.init <preset>` | — | Initialize engagement with workflow preset |
| `/engage.scope` | 0 | Define targets, ROE, authorization |
| `/engage.recon` | 1 | Passive/active reconnaissance |
| `/engage.weaponize` | 2 | Payload development, exploit design |
| `/engage.deliver` | 3 | Delivery vector execution |
| `/engage.exploit` | 4 | Exploitation, finding documentation |
| `/engage.install` | 5 | Persistence establishment |
| `/engage.c2` | 6 | C2 infrastructure setup |
| `/engage.actions` | 7 | Objectives execution, lateral movement |
| `/engage.report` | 8 | Report generation |
| `/engage.status` | — | Show pipeline status and progress |
| `/engage.gate` | — | Validate current phase gate |

### Workflow Presets

| Preset | Phases | Use Case |
|--------|--------|----------|
| `web-app` | 0,1,2,3,4,8 | OWASP-focused web application assessment |
| `network` | 0,1,2,4,5,6,7,8 | Internal network penetration test |
| `red-team` | ALL (0-8) | Full adversary simulation |
| `cloud` | 0,1,4,8 | AWS/Azure/GCP security audit |
| `mobile` | 0,1,2,4,8 | Android/iOS application pentest |
| `ad-domain` | 0,1,2,4,5,7,8 | Active Directory domain assessment |
| `bug-bounty` | 0,1,4,8 | Bug bounty vulnerability hunting |

### Quality Gates

Each phase transition validates:
- Required artifacts exist (templates filled)
- Findings have mandatory fields (CWE, CVSS, evidence, ATT&CK ID)
- Gate PASS → suggests next phase + relevant skills
- Gate FAIL → lists missing items

## Structure

```
.
├── skills/                        # 31 skill modules (progressive-disclosure layout)
│   ├── recon-osint/
│   │   ├── SKILL.md               #   thin router: when-to-activate + technique map + OPSEC/detection
│   │   ├── references/            #   per-skill technique deep-dives (theory + code + detection + OPSEC)
│   │   └── scripts/               #   runnable tooling backing each technique
│   ├── coding-mastery/scripts/_lib/  # shared safety libs: scope_guard, action_guard, http_creds, redact_headers
│   ├── engagement-memory/         #   cross-engagement pattern-learning memory (support skill)
│   ├── using-offensive-claude/    #   SessionStart DISPATCHER — skill-invocation discipline
│   ├── engagement-flow/           #   process skills: sequence the kill chain,
│   ├── scope-discipline/          #   no target without authorization,
│   ├── finding-discipline/        #   no [CONFIRMED] without proof,
│   ├── opsec-discipline/          #   detection/cleanup/redaction before acting,
│   ├── writing-offensive-skills/  #   authoring conventions
│   ├── exploit-development/
│   ├── ...
│   └── references/                # shared 47-file vulnerability pattern library
├── .claude-plugin/                # plugin.json + marketplace.json (install as a Claude Code plugin)
├── hooks/                         # SessionStart hook that injects the dispatcher every session
├── agents/                        # 7 collaborative sub-agents (incl. finding-validator)
├── engine/                        # bounded, resumable, traceable autopilot runner
│   ├── engine.py                  #   phase runner (budget + loop-detect + trace + resume; not an LLM)
│   ├── budget.py  loop_detector.py  tracer.py
├── tests/                         # pytest suite for the safety-critical scripts (run: pytest)
├── templates/                     # Structured templates per Kill Chain phase
│   ├── scope/                     #   scope-definition + scope.schema.json/example (machine-readable ROE)
│   └── ... (recon, weaponize, delivery, exploit, install, c2, actions, report)
├── workflows/                     # Kill Chain workflow definitions (YAML) + WORKFLOW-ENGINE.md
├── commands/                      # /engage.* orchestration slash commands (incl. memory, pickup)
├── presets/                       # Engagement type presets (7 presets)
├── .github/                       # SECURITY.md (coordinated disclosure) + CI (workflows/tests.yml)
├── TERMS.md                       # Acceptable-use policy / authorization requirement
├── CLAUDE.md                      # System prompt & behavior config
├── settings.json                  # Claude Code settings, permissions, MCP servers
├── install.sh                     # One-liner install script
└── README.md
```

## Safety, Testing & Autonomy

The framework's safety controls are **executable, not prose**, and covered by an automated test suite:

| Control | What it does |
|---------|--------------|
| `scope_guard.py` | Enforces the engagement scope (`scope.json`); host parsing matches HTTP clients (userinfo/IPv6/IDN safe), fails closed |
| `validate_findings.py` | Evidence-grounding + per-class false-positive harness using structured proof signals |
| `action_guard.py` | 3-state gate (allow / require_approval / block): out-of-scope → block, safe-method policy, per-host circuit breaker |
| `redact_headers.py` | Masks Authorization/Cookie/API-key/JWT at the data boundary (fail-closed) before traffic reaches the model |
| `engagement-memory/` | Persists confirmed findings as impact-ranked patterns; recalls top-N prior techniques at recon/weaponize |
| `engine/` | Bounded autopilot: hard step/time budget, loop detection, append-only trace, `--resume`; offensive actions stay operator-gated |
| `tests/` + CI | `pytest` suite (run `pytest`); GitHub Actions runs it + byte-compile + shellcheck on every push |

All safety code is adversarially red-teamed and regression-tested. See [`TERMS.md`](TERMS.md) for the
authorization requirement — every request the toolkit sends is the operator's responsibility.

## Skill-Invocation Discipline (dispatcher + process skills)

Installed as a plugin, a **SessionStart hook** injects the `using-offensive-claude` dispatcher into
every conversation: *if there's even a 1% chance a skill applies, invoke it before acting.* Process /
discipline skills come **before** domain skills (the offensive analog of brainstorming / TDD / debugging):

| Process skill | Rule | Backed by |
|---------------|------|-----------|
| `engagement-flow` | Sequence the kill chain with quality gates | `/engage.*`, `engine/` |
| `scope-discipline` | **No target without authorization** | `scope_guard.py`, `action_guard.py` |
| `finding-discipline` | **No `[CONFIRMED]` without proof** | `validate_findings.py`, `finding-validator` |
| `opsec-discipline` | Decide detection / cleanup / redaction before acting | `redact_headers.py` |
| `writing-offensive-skills` | Conventions for authoring skills in this repo | — |

Each discipline skill carries an Iron Law + Red-Flags + Rationalizations table (resists shortcutting
under pressure). The dispatcher auto-loads; domain skills below are invoked via the `Skill` tool.

## Skills (31 domain)

Each skill is a progressive-disclosure module: a thin `SKILL.md` router (when-to-activate, a technique
map of *technique → ATT&CK ID → CWE → reference → script*, and an OPSEC/detection summary), backed by
per-skill `references/` deep-dives and runnable `scripts/`. Every technique pairs the offensive path with
a Sigma/EDR detection signature and OPSEC notes, and cites current (2024–2026) CVEs/techniques.
Descriptions use `Use when…` triggers so the dispatcher routes to the right skill.

| # | Skill | Kill Chain | Coverage |
|---|-------|-----------|----------|
| 01 | recon-osint | Recon | Subdomain enum, CVE lookup, breach intel, DNS history, Shodan/Censys |
| 02 | vulnerability-analysis | Recon, Exploit | Taint analysis, source-sink tracing, false positive discipline |
| 03 | exploit-development | Weaponize, Exploit | ROP chains, heap exploitation, shellcode, deserialization, mitigation bypass |
| 04 | reverse-engineering | Weaponize, Exploit | IDA/Ghidra, Frida, angr, firmware extraction, anti-RE bypass |
| 05 | web-pentest | Delivery, Exploit | SQLi, XSS, SSRF, race conditions, GraphQL, JWT, business logic |
| 06 | network-attack | Recon, Actions | AD exploitation, lateral movement, pivoting, wireless, protocol attacks |
| 07 | red-team-ops | Install, Actions | C2, persistence, privesc, defense evasion, LOLBins, exfiltration |
| 08 | cloud-security | Recon, Exploit | AWS/Azure/GCP privesc, container escape, Kubernetes, IaC review |
| 09 | malware-analysis | Weaponize | Static/dynamic analysis, YARA rules, unpacking, C2 protocol RE |
| 10 | ai-security | Recon, Exploit | Prompt injection, RAG poisoning, model extraction, adversarial ML |
| 11 | threat-hunting | Report | MITRE ATT&CK mapping, Sigma rules, log correlation, behavioral detection |
| 12 | privesc-linux | Exploit, Actions | SUID, capabilities, sudo, kernel exploits, Docker escape, cron abuse |
| 13 | privesc-windows | Exploit, Actions | Token abuse, service exploitation, UAC bypass, credential harvesting |
| 14 | coding-mastery | Weaponize | Python/C/Go/Rust/ASM for exploit dev, scanners, C2, crypto |
| 15 | crypto-analysis | Recon, Exploit | TLS auditing, hash cracking, RSA attacks, side-channel, implementation review |
| 16 | incident-response | Report | Memory forensics (Volatility), timeline analysis, IOC extraction, containment |
| 17 | edr-evasion | Delivery, Install | Hook unhooking, direct/indirect syscalls, AMSI/ETW bypass, sleep masking |
| 18 | initial-access | Delivery | HTML smuggling, ISO/MOTW bypass, DLL sideload, staged payloads, phishing |
| 19 | shellcode-dev | Weaponize | PEB walk, API hashing, loaders, PE-to-shellcode, cross-platform |
| 20 | windows-mitigations | Exploit | ASLR/DEP/CFG/CET/ACG bypass, WDAC/ASR bypass, PPL exploitation |
| 21 | windows-boundaries | Exploit, Install | Kernel/user boundary, sandbox escape, AppContainer, COM elevation |
| 22 | keylogger-arch | Install, Actions | SetWindowsHookEx, RawInput, direct HID, ETW capture, stealth IOCs |
| 23 | mobile-pentest | Recon, Exploit | Android/iOS, Frida, SSL pinning bypass, exported components, biometric bypass |
| 24 | advanced-redteam | C2, Actions | C2 infra (redirectors, malleable profiles), OPSEC, tiered infrastructure |
| 25 | active-directory-attack | Exploit, Actions | Kerberoasting, NTLM relay, Golden/Silver Ticket, ADCS, delegation abuse |
| 26 | cicd-supply-chain | Weaponize, Delivery | Pipeline poisoning (Actions/GitLab/Jenkins), dependency confusion, OIDC abuse, SLSA/provenance |
| 27 | ai-agent-redteam | Delivery, Exploit | Agentic AI/MCP tool abuse, indirect prompt-injection chains, RAG/memory poisoning, jailbreaks |
| 28 | container-k8s-escape | Exploit, Actions | Container breakout, runc CVEs, K8s RBAC escalation, admission/ingress attacks, node pivot |
| 29 | browser-exploitation | Weaponize, Exploit | V8/JSC JIT type confusion, heap-sandbox & renderer→browser escape, Electron/IPC RCE |
| 30 | macos-offensive | Exploit, Install | TCC/Gatekeeper bypass, keychain, LaunchAgent persistence, ESF evasion *(planned)* |
| 31 | engagement-memory | Recon, Weaponize, Report | Cross-engagement pattern learning — ranked recall of prior techniques *(support)* |

## Agents (7)

| Agent | Layer | Active Phases | Role |
|-------|-------|---------------|------|
| redteam-planner | Planning | Scope, Recon, Weaponize, Actions | Attack path design, OPSEC strategy |
| exploit-researcher | Execution | Recon, Weaponize, Exploit | CVE research, exploit chain development |
| security-reviewer | Analysis | Recon, Exploit, Report | Finding validation, gate checks |
| reverse-engineer | Execution | Weaponize, Exploit, Install | Binary analysis, vulnerability discovery |
| ai-researcher | Execution | Recon, Weaponize, Exploit | AI/ML security assessment |
| network-analyst | Analysis | Recon, Delivery, C2, Actions | Protocol analysis, C2 review |
| finding-validator | Analysis | Exploit, Actions, Report | Adversarial PASS/KILL/DOWNGRADE verdict on findings |

Agents collaborate through structured handoffs — planning agents feed execution agents, execution agents feed analysis agents for validation.

## Vulnerability References (47 files)

Detailed patterns with vulnerable/secure code examples, organized by category:

- **Taint Analysis** (4): source-sink tracing, filter evaluation, threat model, false positive reduction
- **Memory Safety** (7): buffer overflow, integer overflow, UAF, null deref, OOB read, unsafe Rust
- **Injection** (11): SQL, command, XSS, SSRF, SSTI, XXE, deserialization, path traversal, file upload, prototype pollution, ReDoS
- **Authentication** (8): bypass, authorization flaws, session management, hardcoded creds, default creds, brute force, permissions
- **Cryptography** (4): weak algorithms, key management, side-channel, certificate validation
- **Concurrency** (3): race conditions, TOCTOU, established patterns
- **Web/API** (5): CORS, CSRF, open redirect, resource exhaustion, API security
- **Supply Chain** (3): dependency confusion, code integrity, ML model files
- **Active Directory** (1): delegation, GPO abuse, RODC, SCCM/WSUS, ADCS, trust attacks

## MCP Servers

| Server | Purpose |
|--------|---------|
| mitm-search | Web search via mcp.mitm.vn |
| ida-multi-mcp | IDA Pro integration (decompile, rename, xrefs, patching) |
| jadx-mcp-server | Android APK decompilation and analysis |

## How It Works

1. Claude Code reads `CLAUDE.md` — sets offensive security persona with Kill Chain methodology
2. Use `/engage.init <preset>` to start a structured engagement, or use skills standalone
3. Each phase has templates, quality gates, skill mappings, and agent coordination
4. Agents collaborate through structured handoffs — planning → execution → analysis layers
5. Quality gates validate findings before phase transitions (CWE, CVSS, evidence required)
6. Reports are generated from structured finding records with evidence linking

## Customization

- **Add skills:** create `skills/<name>/SKILL.md` with YAML frontmatter including kill_chain metadata
- **Add agents:** create `agents/<name>.md` with layer, phases, and collaboration metadata
- **Add workflows:** create `workflows/<name>.yml` following the workflow schema
- **Add presets:** create `presets/<name>/preset.yml` with phase/skill/agent selection
- **Add templates:** create `templates/<phase>/<name>.md` with gate and dependency metadata
- **Add MCP servers:** edit `mcpServers` in `settings.json`

## Requirements

- Claude Code CLI, Desktop App, or VS Code extension
- For MCP integrations: IDA Pro with ida-multi-mcp plugin, JADX with MCP server


<a href="https://www.star-history.com/?repos=hypnguyen1209/offensive-claude&type=date&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=hypnguyen1209/offensive-claude&type=date&theme=dark&legend=top-left" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=hypnguyen1209/offensive-claude&type=date&legend=top-left" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=hypnguyen1209/offensive-claude&type=date&legend=top-left" />
 </picture>
</a>
