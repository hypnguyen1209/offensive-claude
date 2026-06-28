# Design Spec — Offensive-Claude Skills Professional Upgrade

**Date:** 2026-06-28
**Branch:** `feat/skills-pro-upgrade`
**Status:** Approved — in implementation

## 1. Goal

Transform the 25 single-file skills into 30 professional, multi-file skills using a
progressive-disclosure architecture, and bring every skill to a consistent
professional standard with current (2024-2026) techniques, runnable tooling,
OPSEC/detection pairing, and full MITRE/CWE/CVSS rigor. Applied repo-wide in one
coordinated pass via a multi-agent workflow, executed in batches on a feature branch.

## 2. Architecture — multi-file skill (progressive disclosure)

Each skill becomes a directory with three layers:

```
skills/<name>/
├── SKILL.md              # Navigation layer (~120-180 lines):
│                         #   - When to Activate
│                         #   - Technique Map table: technique -> ATT&CK Txxxx -> CWE -> ref -> script
│                         #   - Concise quick-start workflow
│                         #   - OPSEC & Detection summary table
│                         #   - Routing links into references/ and scripts/
├── references/           # Deep-dive layer (3-7 files/skill, one technique cluster each):
│   └── <cluster>.md      #   theory + 2024-2026 variants + full code +
│                         #   detection signatures (Sigma/EDR) + OPSEC/cleanup + CVE refs
└── scripts/              # Executable layer (runnable tools, no placeholders):
    └── <tool>.{py,ps1,c,go,sh}
```

The shared `skills/references/` library (47 vuln-class files) is preserved. Per-skill
`references/` link to it when topics overlap rather than duplicating content.

### Standardized frontmatter additions

```yaml
kill_chain:
  attck_tactics: [TAxxxx]
  attck_techniques: [Txxxx, Txxxx.yyy]   # NEW: technique-level mapping
references: [references/a.md, ...]         # NEW: routing manifest
scripts: [scripts/a.py, ...]               # NEW: routing manifest
```

## 3. The four professional pillars (every skill)

1. **2024-2026 currency** — web-search-verified CVEs/techniques/tooling; explicit
   affected OS/tool versions; dead/patched techniques removed.
2. **Runnable scripts** — every technique cluster ships >=1 complete tool in `scripts/`
   with usage header and dependency notes. No placeholders, no "left as an exercise".
3. **OPSEC + detection pairing** — every offensive technique pairs with the telemetry
   it generates, a Sigma/EDR detection, IOCs, and OPSEC/cleanup notes.
4. **MITRE/CWE/CVSS rigor** — every technique maps to a technique-level ATT&CK ID
   (Txxxx), a CWE-ID, and findings use the repo finding templates.

## 4. New skills (25 -> 30)

| # | Skill | Domain | Kill Chain |
|---|-------|--------|-----------|
| 26 | `cicd-supply-chain` | CI/CD pipeline poisoning (GitHub Actions/GitLab/Jenkins), advanced dependency confusion, artifact/SLSA tampering, OIDC abuse | Weaponize, Delivery |
| 27 | `ai-agent-redteam` | Agentic AI / tool & MCP abuse, advanced RAG poisoning, indirect prompt-injection chains, memory poisoning (complements `ai-security`) | Delivery, Exploit |
| 28 | `container-k8s-escape` | Container breakout, K8s RBAC abuse, runtime escape (runc CVEs), admission controller bypass, malicious images | Exploit, Actions |
| 29 | `macos-offensive` | TCC bypass, Gatekeeper/notarization, keychain, LaunchAgent persistence, Endpoint Security evasion | Exploit, Install |
| 30 | `browser-exploitation` | V8/JS engine bug classes, renderer->sandbox escape, Electron/IPC abuse, client-side RCE | Weaponize, Exploit |

## 5. Repo-wide consistency updates

- `CLAUDE.md` + `README.md`: skills tables 25 -> 30, updated coverage descriptions.
- `agents/`: route new skills from existing agents (and consider a cloud-native operator agent).
- `presets/` + `workflows/`: map new skills into relevant presets; add `cicd`/`container` presets if warranted.
- `commands/engage.*`: add new-skill mappings to the relevant phases.

## 6. Execution plan (multi-agent workflow, batched)

Run on `feat/skills-pro-upgrade`, in batches of ~6 skills, with these phases:

1. **AUTHOR** (pipeline, per skill): agent reads existing SKILL.md, web-searches
   2024-2026 techniques with citations, then writes the multi-file structure
   (SKILL.md + references/ + scripts/) applying the template and four pillars.
   Agents write to distinct skill directories so there is no write conflict.
2. **VERIFY** (adversarial, per skill): independent reviewer checks the five quality
   gates and returns a pass/fail verdict plus a concrete fix list.
3. **FIX** (conditional): re-author against the fix list when VERIFY fails.
4. **CONSISTENCY** (single-threaded): update CLAUDE.md / README / presets / commands;
   lint frontmatter.
5. **SYNTHESIS**: report what changed per skill, ref/script counts, residual gaps.

## 7. Quality gates (definition of done, per skill)

1. SKILL.md <=180 lines with a technique-map table and routing links.
2. Each technique cluster has a reference file and >=1 runnable script.
3. Every technique carries an ATT&CK Txxxx, a CWE-ID, and a detection signature.
4. At least one 2024-2026 technique/CVE is cited with a source.
5. Adversarial reviewer passes (no placeholders, code is syntactically valid).

## 8. Out of scope

- No changes to the engagement pipeline phases (kill-chain stays 9 phases).
- No new MCP servers.
- The shared `skills/references/` vuln-class library is preserved, not restructured.
