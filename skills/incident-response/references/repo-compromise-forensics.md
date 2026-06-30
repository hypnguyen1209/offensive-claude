# Repository-Compromise Forensics — investigating a poisoned public repo

When a public repo is compromised (a malicious commit slipped in, then a force-push to hide it; a
deleted PR that smuggled a backdoor; a hijacked maintainer account), the attacker controls the repo's
*visible* state but **not** the external, immutable mirrors of its history. This is the post-mortem
playbook (the aws-toolkit-vscode-style investigation) for `incident-response`. It complements the
offensive `cicd-supply-chain` skill — here you are the defender reconstructing what happened.

## The insight: four INDEPENDENT, attacker-uncontrollable sources

An attacker who force-pushes cannot reach into Git's object store, GH Archive, or the Wayback
Machine. Cross-correlate all four — agreement across independent sources is the confidence:

| # | Source | Recovers | Tool |
|---|--------|----------|------|
| 1 | **Dangling/unreachable objects** in a clone | Force-pushed-away commits (object survives) | `dangling_commit_finder.py` (git fsck/reflog via `git_safe`) |
| 2 | **GH Archive** (`data.gharchive.org`) | PushEvent before/after SHAs, deleted PRs/issues, DeleteEvents | `gharchive_recover.py plan` |
| 3 | **Wayback Machine CDX** | Snapshots of PR/issue pages later deleted | `gharchive_recover.py` (wayback queries) |
| 4 | **Live GitHub Events API** | Recent (~90) repo events, free, no creds | `gharchive_recover.py events` |

BigQuery over GH Archive is the heavyweight option and is **optional** — the free Events API + Wayback
+ `git fsck` cover most investigations without any cloud credentials. `gharchive_recover.py` emits the
BigQuery SQL only for when the free sources miss.

## Procedure (hypothesis → verify → check → report)

1. **Collect (fan out).** Reuse `superpowers:dispatching-parallel-agents` to run the four collectors
   in parallel — do **not** build a bespoke orchestrator. Each writes its raw evidence to the
   engagement workspace.
   ```bash
   git clone --mirror https://github.com/OWNER/REPO repo.git    # a mirror keeps all refs/objects
   python skills/incident-response/scripts/dangling_commit_finder.py repo.git --json dangling.json
   python skills/incident-response/scripts/gharchive_recover.py plan OWNER/REPO --from 2026-06-01 --to 2026-06-30 --json plan.json
   # then fetch the Events API / Wayback CDX / GH Archive hours the plan lists (scoped, read-only)
   ```
2. **Form a hypothesis.** "Commit X was force-pushed away on DATE by ACTOR and introduced FILE."
3. **Verify at source (typed, re-verifiable).** Each cited artifact gets a URL + content hash via
   `evidence_kit.py` (`skills/vulnerability-analysis/scripts/evidence_kit.py`) so the finding's
   evidence is re-fetchable and tamper-evident — split "authentic & still true at source?" from
   "does the claim follow?" (finding-validator Q2/Q2.5).
4. **Check (adversarial).** A second, blind reviewer (`finding-checker`) tries to refute the timeline
   from the artifacts alone. Agreement across ≥2 independent sources before you call it confirmed.
5. **Report.** Timeline (UTC), the injected diff (`git show <dangling-sha>`), actor attribution **with
   a confidence level**, and the four-source corroboration. Use `templates/report/`.

## Discipline & OPSEC

- **Untrusted repo:** every git command runs through `safe_subprocess.git_safe` (hooks/prompt/host-
  config/ext-transport/symlinks disabled). Never run a repo's hooks or `npm install` during analysis.
- **Read-only + scoped:** cloning a target is gated by `scope_guard`; keep all evidence in the
  engagement workspace, not host dirs.
- **Attribution is a claim, not a fact:** GitHub actor logins can be spoofed via crafted commits
  (author != committer != pusher). State attribution with a confidence level and corroborate the
  pusher via GH Archive PushEvent `actor`, not just the commit author header.
- **Secrets:** recovered diffs/traces may contain leaked credentials — treat as sensitive, and
  **rotate** anything exposed rather than only noting it.
