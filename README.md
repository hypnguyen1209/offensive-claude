# Offensive Security Research Config for Claude Code

A comprehensive Claude Code configuration tailored for security researchers, red teamers, and vulnerability analysts. Includes 25 specialized skills, 6 agents, and 46 vulnerability reference files covering the full offensive security lifecycle.

## Quick Setup

```bash
# Option 1: Global (all projects)
cp -r . ~/.claude/

# Option 2: Project-specific
cp -r . <your-project>/.claude/
```

Skills and agents activate automatically — no additional configuration needed.

## Structure

```
.
├── CLAUDE.md                  # System prompt & behavior config
├── settings.json              # Claude Code settings, permissions, MCP servers
├── agents/                    # 6 specialized sub-agents (model: opus)
├── skills/                    # 25 offensive/defensive skill modules
│   └── references/            # 46 detailed vulnerability pattern files
└── README.md
```

## Skills (25)

| # | Skill | Coverage |
|---|-------|----------|
| 01 | recon-osint | Subdomain enum, CVE lookup, breach intel, DNS history, Shodan/Censys |
| 02 | vulnerability-analysis | Taint analysis, source-sink tracing, false positive discipline |
| 03 | exploit-development | ROP chains, heap exploitation, shellcode, deserialization, mitigation bypass |
| 04 | reverse-engineering | IDA/Ghidra, Frida, angr, firmware extraction, anti-RE bypass |
| 05 | web-pentest | SQLi, XSS, SSRF, race conditions, GraphQL, JWT, business logic |
| 06 | network-attack | AD exploitation, lateral movement, pivoting, wireless, protocol attacks |
| 07 | red-team-ops | C2, persistence, privesc, defense evasion, LOLBins, exfiltration |
| 08 | cloud-security | AWS/Azure/GCP privesc, container escape, Kubernetes, IaC review |
| 09 | malware-analysis | Static/dynamic analysis, YARA rules, unpacking, C2 protocol RE |
| 10 | ai-security | Prompt injection, RAG poisoning, model extraction, adversarial ML |
| 11 | threat-hunting | MITRE ATT&CK mapping, Sigma rules, log correlation, behavioral detection |
| 12 | privesc-linux | SUID, capabilities, sudo, kernel exploits, Docker escape, cron abuse |
| 13 | privesc-windows | Token abuse, service exploitation, UAC bypass, credential harvesting |
| 14 | coding-mastery | Python/C/Go/Rust/ASM for exploit dev, scanners, C2, crypto |
| 15 | crypto-analysis | TLS auditing, hash cracking, RSA attacks, side-channel, implementation review |
| 16 | incident-response | Memory forensics (Volatility), timeline analysis, IOC extraction, containment |
| 17 | edr-evasion | Hook unhooking, direct/indirect syscalls, AMSI/ETW bypass, sleep masking |
| 18 | initial-access | HTML smuggling, ISO/MOTW bypass, DLL sideload, staged payloads, phishing |
| 19 | shellcode-dev | PEB walk, API hashing, loaders, PE-to-shellcode, cross-platform |
| 20 | windows-mitigations | ASLR/DEP/CFG/CET/ACG bypass, WDAC/ASR bypass, PPL exploitation |
| 21 | windows-boundaries | Kernel/user boundary, sandbox escape, AppContainer, COM elevation |
| 22 | keylogger-arch | SetWindowsHookEx, RawInput, direct HID, ETW capture, stealth IOCs |
| 23 | mobile-pentest | Android/iOS, Frida, SSL pinning bypass, exported components, biometric bypass |
| 24 | advanced-redteam | C2 infra (redirectors, malleable profiles), OPSEC, tiered infrastructure |
| 25 | active-directory-attack | Kerberoasting, NTLM relay, Golden/Silver Ticket, ADCS, delegation abuse |

## Agents (6)

| Agent | Role |
|-------|------|
| redteam-planner | Designs attack paths, C2 infrastructure, OPSEC strategies |
| exploit-researcher | CVE research, patch diffing, exploitation chain development |
| security-reviewer | Deep code security audit with exploitability validation |
| reverse-engineer | Binary/firmware analysis, vulnerability discovery in compiled code |
| ai-researcher | ML architecture, training optimization, interpretability, safety |
| network-analyst | Packet analysis, protocol dissection, IDS/IPS rule creation |

## Vulnerability References (46 files)

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

1. Claude Code reads `CLAUDE.md` as the system prompt — sets offensive security persona
2. Skills activate contextually based on your question/task
3. Agents can be spawned as sub-agents for parallel or specialized work
4. Reference files are loaded on-demand when deeper vulnerability patterns are needed

## Customization

- Add new skills: create `skills/XX-name.md` with YAML frontmatter
- Add new agents: create `agents/name.md` with role description
- Add MCP servers: edit `mcpServers` in `settings.json`
- Modify permissions: edit `permissions.allow` in `settings.json`

## Requirements

- Claude Code CLI, Desktop App, or VS Code extension
- For MCP integrations: IDA Pro with ida-multi-mcp plugin, JADX with MCP server
