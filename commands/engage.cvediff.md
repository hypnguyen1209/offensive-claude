---
description: Find the canonical fix commit(s) for a CVE across sources, then diff for root cause
---

# /engage.cvediff

Locates the fix commit(s) for a CVE across OSV / NVD / GitHub Advisories, de-duplicates them, and
optionally clones (scope-gated, hardened) to emit `git diff fix^..fix` — the start of n-day patch
diffing. Feeds `reverse-engineering/references/patch-diffing-protocol.md` and can chain into
`/engage.crash` for root-cause + exploitability.

## Usage

`/engage.cvediff <CVE-id> [--source osv,nvd,ghsa] [--diff --repo <url> --sha <fix>]`

## Process

1. **Discover** — `cve_diff.py find <CVE>` queries each source, extracts every commit reference
   (github/gitlab/cgit + OSV GIT-range `fixed` events), merges by (repo, sha). A source that errors
   is recorded, not fatal.
2. **Pick the canonical fix** — prefer a commit confirmed by ≥2 sources (`also_in`); verify the SHA
   exists in the repo before trusting it.
3. **Diff (gated)** — `cve_diff.py diff <CVE> --repo <url> --sha <fix> --scope .engage/scope/scope.json`.
   The repo host is checked against `scope_guard` FIRST (out-of-scope ⇒ refused, exit 3); the clone
   runs through `safe_subprocess.git_safe` (no hooks/prompt/host-config/ext-transport/symlinks).
4. **Root cause** — feed the diff into patch-diffing (BinDiff/ghidriff for binaries) or read it
   directly; optionally `/engage.crash` to prove reachability + empirical exploitability.

## Notes
- Read-only public advisory APIs; the clone is the only state-changing step and it is scope-gated.
- A missing/own­ership-changed fix commit is common — corroborate across sources; a single source is
  often wrong or stale.
