# Offensive Security Research Config for Claude Code

A spec-driven offensive security framework for Claude Code — structured engagement workflows based on the Cyber Kill Chain, 32 kill-chain skills (multi-file progressive-disclosure) plus a **discipline layer** (a SessionStart dispatcher + 6 process/discipline skills), 8 collaborative agents, and a shared 47-file vulnerability reference library. Inspired by [GitHub's spec-kit](https://github.com/github/spec-kit), [obra/superpowers](https://github.com/obra/superpowers), and [gadievron/raptor](https://github.com/gadievron/raptor) (crash→exploitability + OSS-repo forensics).

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
| `/engage.crash` | 4 | Crash → root cause (rr) → reachability (gcov/trace) → empirical exploitability verdict |
| `/engage.cvediff` | 2,4 | Find a CVE's canonical fix commit(s) across sources, then scope-gated diff for root cause |
| `/engage.scorecard` | — | Calibrate model verdict trust (Wilson-bounded miss-rate) to short-circuit re-validation |
| `/engage.threatmodel` | 1 | Materialize / lint / drift-check the engagement threat model |
| `/engage.memory` | — | Recall prior patterns / record confirmed findings (cross-engagement learning) |
| `/engage.pickup` | — | Resume an engagement from the engine trace (skip completed steps) |

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
├── skills/                        # 32 skill modules (progressive-disclosure layout)
│   ├── recon-osint/
│   │   ├── SKILL.md               #   thin router: when-to-activate + technique map + OPSEC/detection
│   │   ├── references/            #   per-skill technique deep-dives (theory + code + detection + OPSEC)
│   │   └── scripts/               #   runnable tooling backing each technique
│   ├── coding-mastery/scripts/_lib/  # shared safety libs: scope_guard, action_guard, http_creds, redact_headers
│   ├── engagement-memory/         #   cross-engagement pattern-learning memory (support skill)
│   ├── using-offensive-claude/    #   SessionStart DISPATCHER — skill-invocation discipline
│   ├── engagement-flow/           #   process skills: sequence the kill chain,
│   ├── scope-discipline/          #   no target without authorization,
│   ├── threat-model-discipline/   #   model the attack surface + detect drift before exploiting,
│   ├── finding-discipline/        #   no [CONFIRMED] without proof,
│   ├── opsec-discipline/          #   detection/cleanup/redaction before acting,
│   ├── writing-offensive-skills/  #   authoring conventions
│   ├── exploit-development/
│   ├── ...
│   └── references/                # shared 47-file vulnerability pattern library
├── .claude-plugin/                # plugin.json + marketplace.json (install as a Claude Code plugin)
├── hooks/                         # SessionStart hook that injects the dispatcher every session
├── .devcontainer/                 # reproducible binary-analysis toolchain (rr/gdb/gcov/afl++) for the
│                                  #   crash→exploitability pipeline; scoped SYS_PTRACE/SYS_PERFMON, not --privileged
├── agents/                        # 8 collaborative sub-agents (incl. finding-validator, finding-checker)
├── engine/                        # bounded, resumable, traceable autopilot runner
│   ├── engine.py                  #   phase runner (budget + loop-detect + trace + resume; not an LLM)
│   ├── budget.py  loop_detector.py  tracer.py
│   ├── rebuttal.py                #   bounded generator↔checker rebuttal loop (default-to-skeptic)
│   └── model_scorecard.py         #   Wilson-bounded, fail-closed model-verdict trust calibration
├── tests/                         # pytest suite for the safety-critical scripts (run: pytest)
├── templates/                     # Structured templates per Kill Chain phase
│   ├── scope/                     #   scope-definition + scope.schema.json/example (machine-readable ROE)
│   ├── threat-model/              #   threat model (assets/entry-points/boundaries/ATT&CK) + drift baseline
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
| `validate_findings.py` | Evidence-grounding + per-class FP harness via structured proof signals; native-bug reachability bar (gcov/trace) + `[EVD-XXX]` citation gate (`evidence_kit.py` re-verifiable evidence) |
| `safe_subprocess.py` | Hardened exec for untrusted inputs/repos: shell=False, clean env, bounded+fail-closed, UTF-8 decode, `git_safe()` (hooks/prompt/host-config/ext-transport disabled) |
| `action_guard.py` | 3-state gate (allow / require_approval / block): out-of-scope → block, safe-method policy, per-host circuit breaker |
| `redact_headers.py` | Masks Authorization/Cookie/API-key/JWT at the data boundary (fail-closed) before traffic reaches the model |
| `finding-checker` + `engine/rebuttal.py` | Blind artifact-only adversarial checker driving a bounded generator↔checker rebuttal loop (default-to-skeptic; EXHAUSTED/STALLED never accept) |
| `engine/model_scorecard.py` | Fail-closed model-verdict trust calibration (Wilson 95% upper-bound miss-rate) to short-circuit re-validation only on a proven track record |
| `engagement-memory/` | Persists confirmed findings as impact-ranked patterns; recalls top-N prior techniques at recon/weaponize |
| `engine/` | Bounded autopilot: hard step/time budget, loop detection, append-only trace, `--resume`; offensive actions stay operator-gated |
| `tests/` + CI | `pytest` suite (run `pytest`); GitHub Actions runs it + byte-compile (`skills/` + `engine/`) + shellcheck on every push |

All safety code is adversarially red-teamed and regression-tested. See [`TERMS.md`](TERMS.md) for the
authorization requirement — every request the toolkit sends is the operator's responsibility.

### Crash → Exploitability Pipeline

For native memory-corruption work, a staged-proof pipeline turns "it crashes" into a defensible,
artefact-backed exploitability verdict — run via `/engage.crash` in the `.devcontainer/` toolchain:

1. **Root cause** — `rr` deterministic record/replay reverse-steps to the corrupting write
   (`rr_root_cause.sh`, emits a `trace_proof`).
2. **Reachability** — `gcov` line-hit / function trace proves the vulnerable line actually ran; the
   harness will not mark a native bug `[CONFIRMED]` without a `coverage_proof`/`trace_proof`.
3. **Empirical feasibility** — rebuild the crash witness under permissive/distro/hardened/asan
   profiles and record which still fire (`feasibility_profile.py`); `exploit_context.py` then forbids
   `/exploit` from using a technique the empirical mitigation map marks blocked.
4. **Path feasibility** — branch guards → tri-state SAT/UNSAT (`path_conditions.py`, Z3 optional;
   a tool limit is `null`/manual, never a false "infeasible").

Supporting tools: `evidence_kit.py` (typed, re-verifiable `[EVD-XXX]` evidence), `variant_hunt.py`
(one finding → all siblings, clustered by root cause), `cve_diff.py` (multi-source fix-commit discovery
→ scope-gated diff), and the `incident-response` repo-compromise forensics kit.

## Skill-Invocation Discipline (dispatcher + process skills)

Installed as a plugin, a **SessionStart hook** injects the `using-offensive-claude` dispatcher into
every conversation: *if there's even a 1% chance a skill applies, invoke it before acting.* Process /
discipline skills come **before** domain skills (the offensive analog of brainstorming / TDD / debugging):

| Process skill | Rule | Backed by |
|---------------|------|-----------|
| `engagement-flow` | Sequence the kill chain with quality gates | `/engage.*`, `engine/` |
| `scope-discipline` | **No target without authorization** | `scope_guard.py`, `action_guard.py` |
| `threat-model-discipline` | Model the attack surface + detect drift before exploiting | `threatmodel_lint.py`, `/engage.threatmodel` |
| `finding-discipline` | **No `[CONFIRMED]` without proof** | `validate_findings.py`, `finding-validator`, `finding-checker` |
| `opsec-discipline` | Decide detection / cleanup / redaction before acting | `redact_headers.py` |
| `writing-offensive-skills` | Conventions for authoring skills in this repo | — |

Each discipline skill carries an Iron Law + Red-Flags + Rationalizations table (resists shortcutting
under pressure). The dispatcher auto-loads; domain skills below are invoked via the `Skill` tool.

## Skills (32 domain)

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
| 16 | incident-response | Report | Memory forensics (Volatility), timeline analysis, IOC extraction, containment, repo/OSS-compromise forensics (dangling-commit recovery, GH Archive / Wayback / Events API) |
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
| 32 | wireless-rf | Recon, Exploit, Actions | Non-Wi-Fi radio: Bluetooth/BLE (GATT, crackle, KNOB/BIAS), Zigbee/Thread/Matter & Z-Wave mesh, LoRaWAN/Sub-GHz capture-replay |

## Agents (8)

| Agent | Layer | Active Phases | Role |
|-------|-------|---------------|------|
| redteam-planner | Planning | Scope, Recon, Weaponize, Actions | Attack path design, OPSEC strategy |
| exploit-researcher | Execution | Recon, Weaponize, Exploit | CVE research, exploit chain development |
| security-reviewer | Analysis | Recon, Exploit, Report | Finding validation, gate checks |
| reverse-engineer | Execution | Weaponize, Exploit, Install | Binary analysis, vulnerability discovery |
| ai-researcher | Execution | Recon, Weaponize, Exploit | AI/ML security assessment |
| network-analyst | Analysis | Recon, Delivery, C2, Actions | Protocol analysis, C2 review |
| finding-validator | Analysis | Exploit, Actions, Report | Adversarial PASS/KILL/DOWNGRADE verdict on findings |
| finding-checker | Analysis | Exploit, Actions, Report | Blind artifact-only checker driving the bounded generator↔checker rebuttal loop |

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


## 🌐 Web Resources & Aesthetic Symbols Index
- [SYM 1F60B](https://coquette-aesthetic-symbols-62.pages.dev/symbol/sym-1f60b/)
- [INSTAGRAM BIO](https://scholar-rune-symbols-77.pages.dev/instagram-bio/)
- [SYM 1F640](https://occult-rune-symbols-64.pages.dev/symbol/sym-1f640/)
- [SYM 2673](https://minimal-star-symbols-43.pages.dev/symbol/sym-2673/)
- [ARROWS LINES](https://pastel-moe-emoticons-55.pages.dev/es/arrows-lines/)
- [SYM 1F635](https://zen-aesthetic-fonts-87.pages.dev/symbol/sym-1f635/)
- [ZODIAC CELESTIAL](https://alchemical-symbol-hub-52.pages.dev/ru/zodiac-celestial/)
- [SYM 26BA](https://coquette-aesthetic-symbols-63.pages.dev/symbol/sym-26ba/)
- [SYM 268F](https://minimal-star-symbols-26.pages.dev/symbol/sym-268f/)
- [SYM 1D460](https://modern-bullet-symbols-45.pages.dev/symbol/sym-1d460/)
- [CLOCKWISE OPEN CIRCLE ARROW](https://minimal-star-symbols-26.pages.dev/symbol/clockwise-open-circle-arrow/)
- [SYM 1F63B](https://scholarly-runes-text-68.pages.dev/symbol/sym-1f63b/)
- [SYM 26EB](https://zen-spacing-text-68.pages.dev/symbol/sym-26eb/)
- [SYM 1F60A](https://techwear-bio-symbols-45.pages.dev/symbol/sym-1f60a/)
- [SYM 1F974](https://soft-pink-fonts-41.pages.dev/symbol/sym-1f974/)
- [SYM 2738](https://gothic-bio-fonts-61.pages.dev/symbol/sym-2738/)
- [SYM 1D472](https://pastel-moe-emoticons-55.pages.dev/symbol/sym-1d472/)
- [DISCORD STATUS](https://clean-mono-fonts-64.pages.dev/ru/discord-status/)
- [SYM 1D421](https://scholarly-runes-text-68.pages.dev/symbol/sym-1d421/)
- [SYM 1F47D](https://gothic-bio-fonts-61.pages.dev/symbol/sym-1f47d/)
- [SYM 1D47D](https://moe-soft-emoticons-41.pages.dev/symbol/sym-1d47d/)
- [SYM 1D420](https://scholarly-runes-text-68.pages.dev/symbol/sym-1d420/)
- [SYM 1F633](https://minimal-star-symbols-91.pages.dev/symbol/sym-1f633/)
- [HEARTS](https://angelic-bow-symbols-76.pages.dev/ja/hearts/)
- [SYM 1D459](https://minimal-star-symbols-91.pages.dev/symbol/sym-1d459/)
- [SYM 1D42B](https://scholarly-runes-text-68.pages.dev/symbol/sym-1d42b/)
- [SYM 26F8](https://matrix-glitch-text-59.pages.dev/symbol/sym-26f8/)
- [SYM 2635](https://gothic-bio-fonts-69.pages.dev/symbol/sym-2635/)
- [SYM 1D422](https://zen-aesthetic-fonts-87.pages.dev/symbol/sym-1d422/)
- [SYM 2636](https://coquette-aesthetic-symbols-96.pages.dev/symbol/sym-2636/)
- [SYM 1F635 200D 1F4AB](https://modern-bullet-symbols-45.pages.dev/symbol/sym-1f635-200d-1f4ab/)
- [SYM 1F630](https://glitch-matrix-fonts-28.pages.dev/symbol/sym-1f630/)
- [SYM 26F3](https://balletcore-unicode-67.pages.dev/symbol/sym-26f3/)
- [SYM 2668](https://glitch-matrix-fonts-28.pages.dev/symbol/sym-2668/)
- [SYM 1D406](https://neon-gamer-symbols-64.pages.dev/symbol/sym-1d406/)
- [LEFT MATHEMATICAL WHITE SQUARE BRACKET](https://anime-sparkle-text-14.pages.dev/symbol/left-mathematical-white-square-bracket/)
- [SYM 1D488](https://sleek-arrow-symbols-42.pages.dev/symbol/sym-1d488/)
- [SYM 26F7](https://clean-mono-fonts-64.pages.dev/symbol/sym-26f7/)
- [SKULL AND CROSSBONES](https://minimal-star-symbols-91.pages.dev/symbol/skull-and-crossbones/)
- [SYM 2634](https://neon-gamer-symbols-64.pages.dev/symbol/sym-2634/)
- [SYM 260D](https://neon-gamer-symbols-64.pages.dev/symbol/sym-260d/)
- [SYM 1F913](https://synthwave-text-vault-95.pages.dev/symbol/sym-1f913/)
- [SYM 2642](https://minimal-star-symbols-91.pages.dev/symbol/sym-2642/)
- [TRENDING](https://minimal-star-symbols-91.pages.dev/ja/trending/)
- [SYM 1D453](https://anime-sparkle-text-14.pages.dev/symbol/sym-1d453/)
- [SYM 26B5](https://scholarly-runes-text-68.pages.dev/symbol/sym-26b5/)
- [SYM 26C2](https://gothic-bio-fonts-61.pages.dev/symbol/sym-26c2/)
- [SYM 26F6](https://minimal-star-symbols-43.pages.dev/symbol/sym-26f6/)
- [SYM 1D414](https://minimal-star-symbols-43.pages.dev/symbol/sym-1d414/)
- [BLACK STAR](https://sleek-arrow-symbols-42.pages.dev/symbol/black-star/)
- [SYM 265D](https://neon-gamer-symbols-64.pages.dev/symbol/sym-265d/)
- [SYM 1D45C](https://kawaii-kaomoji-hub-51.pages.dev/symbol/sym-1d45c/)
- [SYM 1F639](https://balletcore-unicode-67.pages.dev/symbol/sym-1f639/)
- [SYM 2722](https://gothic-bio-fonts-61.pages.dev/symbol/sym-2722/)
- [EIGHT POINTED BLACK STAR](https://soft-pink-fonts-41.pages.dev/symbol/eight-pointed-black-star/)
- [SYM 2611](https://gothic-bio-fonts-61.pages.dev/symbol/sym-2611/)
- [GOTHIC OBSIDIAN SKULL CREST](https://gothic-bio-fonts-69.pages.dev/symbol/gothic-obsidian-skull-crest/)
- [KAOMOJI](https://vintage-script-symbols-65.pages.dev/vi/kaomoji/)
- [DISCORD STATUS](https://anime-sparkle-text-14.pages.dev/ja/discord-status/)
- [SYM 26E6](https://coquette-aesthetic-symbols-96.pages.dev/symbol/sym-26e6/)
- [SYM 1D46D](https://synthwave-text-vault-95.pages.dev/symbol/sym-1d46d/)
- [SYM 2733](https://aesthetic-spacing-fonts-10.pages.dev/symbol/sym-2733/)
- [SYM 1F612](https://angelic-ribbon-text-78.pages.dev/symbol/sym-1f612/)
- [TWELVE POINTED STAR](https://anime-sparkle-text-81.pages.dev/symbol/twelve-pointed-star/)
- [SYM 1D425](https://kawaii-kaomoji-hub-51.pages.dev/symbol/sym-1d425/)
- [SYM 1F63A](https://glitch-matrix-fonts-28.pages.dev/symbol/sym-1f63a/)
- [GAMING WEAPONS](https://zen-aesthetic-fonts-87.pages.dev/es/gaming-weapons/)
- [SYM 273D](https://angelic-bow-symbols-76.pages.dev/symbol/sym-273d/)
- [HEARTS](https://dark-poetry-fonts-30.pages.dev/ja/hearts/)
- [CIRCLED STAR](https://sleek-line-unicode-29.pages.dev/symbol/circled-star/)
- [SYM 2659](https://neon-gamer-symbols-64.pages.dev/symbol/sym-2659/)
- [SYM 267D](https://anime-sparkle-text-14.pages.dev/symbol/sym-267d/)
- [SYM 2668](https://neon-gamer-symbols-64.pages.dev/symbol/sym-2668/)
- [SYM 1F638](https://anime-sparkle-text-14.pages.dev/symbol/sym-1f638/)
- [CHEERING FIGHTING FIST KAOMOJI](https://kawaii-kaomoji-hub-51.pages.dev/symbol/cheering-fighting-fist-kaomoji/)
- [SYM 263F](https://angelic-bow-symbols-76.pages.dev/symbol/sym-263f/)
- [NATURE FLOWERS](https://modern-bullet-symbols-45.pages.dev/vi/nature-flowers/)
- [SYM 2681](https://sleek-line-unicode-29.pages.dev/symbol/sym-2681/)
- [SYM 268F](https://aesthetic-spacing-fonts-10.pages.dev/symbol/sym-268f/)
- [SYM 1D427](https://mecha-crosshair-tags-20.pages.dev/symbol/sym-1d427/)
- [SYM 1D48C](https://kawaii-kaomoji-hub-51.pages.dev/symbol/sym-1d48c/)
- [SYM 26F1](https://kawaii-kaomoji-hub-51.pages.dev/symbol/sym-26f1/)
- [SYM 1F495](https://glitch-matrix-fonts-28.pages.dev/symbol/sym-1f495/)
- [SYM 273B](https://sleek-line-unicode-29.pages.dev/symbol/sym-273b/)
- [SYM 1F614](https://anime-sparkle-text-14.pages.dev/symbol/sym-1f614/)
- [TRENDING](https://gothic-bio-fonts-69.pages.dev/trending/)
- [SYM 1F976](https://mecha-crosshair-tags-20.pages.dev/symbol/sym-1f976/)
- [SYM 2677](https://chibi-kaomoji-vault-58.pages.dev/symbol/sym-2677/)
- [SYM 1F618](https://zen-unicode-symbols-89.pages.dev/symbol/sym-1f618/)
- [LEFT WING CLAN FLARE](https://sleek-line-unicode-29.pages.dev/symbol/left-wing-clan-flare/)
- [CLOCKWISE OPEN CIRCLE ARROW](https://chibi-kaomoji-vault-58.pages.dev/symbol/clockwise-open-circle-arrow/)
- [INSTAGRAM BIO](https://scholarly-runes-text-68.pages.dev/es/instagram-bio/)
- [SYM 2660](https://manga-emotion-symbols-69.pages.dev/symbol/sym-2660/)
- [SYM 1F92A](https://minimal-star-symbols-91.pages.dev/symbol/sym-1f92a/)
- [ROBLOX NAMES](https://minimal-star-symbols-91.pages.dev/roblox-names/)
- [SYM 1F49F](https://sleek-line-unicode-29.pages.dev/symbol/sym-1f49f/)
- [SYM 2749](https://neon-gamer-symbols-64.pages.dev/symbol/sym-2749/)
- [SYM 1F605](https://angelic-bow-symbols-76.pages.dev/symbol/sym-1f605/)
- [ARROWS LINES](https://minimal-star-symbols-26.pages.dev/pt/arrows-lines/)
- [RIGHT WING CLAN FLARE](https://chibi-kaomoji-vault-58.pages.dev/symbol/right-wing-clan-flare/)
- [SYM 1F925](https://chibi-kaomoji-vault-58.pages.dev/symbol/sym-1f925/)
- [SYM 1F623](https://gothic-bio-fonts-69.pages.dev/symbol/sym-1f623/)
- [STARRY ELEVATION AURA](https://cyber-clan-tags-69.pages.dev/symbol/starry-elevation-aura/)
- [RIGHT WHITE CORNER BRACKET](https://scholarly-runes-text-68.pages.dev/symbol/right-white-corner-bracket/)
- [CIRCLED STAR](https://balletcore-unicode-67.pages.dev/symbol/circled-star/)
- [SYM 1F495](https://gothic-bio-fonts-69.pages.dev/symbol/sym-1f495/)
- [ZODIAC CELESTIAL](https://minimal-star-symbols-26.pages.dev/ja/zodiac-celestial/)
- [ARROWS LINES](https://mecha-crosshair-tags-20.pages.dev/es/arrows-lines/)
- [SYM 273B](https://minimal-star-symbols-91.pages.dev/symbol/sym-273b/)
- [SYM 1D45C](https://alchemist-symbol-hub-29.pages.dev/symbol/sym-1d45c/)
- [ZODIAC CELESTIAL](https://gothic-bio-fonts-69.pages.dev/vi/zodiac-celestial/)
- [SYM 1D48E](https://kawaii-kaomoji-hub-51.pages.dev/symbol/sym-1d48e/)
- [LEO ZODIAC LION](https://mecha-crosshair-tags-20.pages.dev/symbol/leo-zodiac-lion/)
- [CUTE BUNNY RABBIT FACE](https://anime-sparkle-text-14.pages.dev/symbol/cute-bunny-rabbit-face/)
- [HEARTS](https://gothic-bio-fonts-69.pages.dev/ru/hearts/)
- [SYM 1F611](https://glitch-matrix-fonts-28.pages.dev/symbol/sym-1f611/)
- [BRACKETS](https://minimal-star-symbols-26.pages.dev/vi/brackets/)
- [ZODIAC CELESTIAL](https://gothic-bio-fonts-69.pages.dev/es/zodiac-celestial/)
- [SYM 1D458](https://zen-aesthetic-fonts-87.pages.dev/symbol/sym-1d458/)
- [SYM 1F479](https://gothic-bio-fonts-69.pages.dev/symbol/sym-1f479/)
- [SYM 1F925](https://mecha-crosshair-tags-20.pages.dev/symbol/sym-1f925/)
- [SYM 1D414](https://pastel-moe-emoticons-55.pages.dev/symbol/sym-1d414/)
- [SYM 26A3](https://mecha-gamer-fonts-53.pages.dev/symbol/sym-26a3/)
- [SYM 26A5](https://cyber-clan-tags-69.pages.dev/symbol/sym-26a5/)
- [FREEFIRE NAMES](https://cyber-clan-tags-69.pages.dev/vi/freefire-names/)
- [SYM 1F642](https://soft-pink-fonts-41.pages.dev/symbol/sym-1f642/)
- [SYM 2741](https://zen-aesthetic-fonts-87.pages.dev/symbol/sym-2741/)
- [SYM 26EA](https://minimal-star-symbols-43.pages.dev/symbol/sym-26ea/)
- [SYM 1F60F](https://neon-glitch-fonts-20.pages.dev/symbol/sym-1f60f/)
- [AESTHETIC STARDUST COMBO](https://kawaii-kaomoji-hub-51.pages.dev/symbol/aesthetic-stardust-combo/)
