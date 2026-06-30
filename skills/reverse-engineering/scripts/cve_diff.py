#!/usr/bin/env python3
"""cve_diff.py - find the canonical FIX COMMIT(s) for a CVE across multiple sources, then diff them.

Patch-diffing an n-day starts with "where is the fix?". Vendors scatter that across OSV, the GitHub
Advisory DB, and NVD; a single source is often missing or wrong. This queries several, extracts every
commit reference (github/gitlab/cgit/generic + OSV's GIT-range `fixed` events), de-duplicates by
(repo, sha), and - on request - clones the repo and emits `git diff fix^..fix` so you can recover the
root cause. Feeds `references/patch-diffing-protocol.md` and can chain into `/engage.crash`.

Network + clone are GATED and isolated:
  - the discovery layer takes an injectable `fetcher` (default urllib) so parsing/merge is testable
    offline and you control whether any request goes out;
  - cloning checks the repo host against scope_guard FIRST and runs git through safe_subprocess.git_safe
    (untrusted-repo hardening: no hooks/prompt/host-config/ext-transport/symlinks).

Pure stdlib. CLI:
  cve_diff.py find CVE-2024-1234 [--source osv,nvd,ghsa] [--json out.json]
  cve_diff.py diff CVE-2024-1234 --repo https://github.com/o/r --sha <fix> --scope scope.json [--workdir d]
  exit 0 ok, 2 error, 3 out-of-scope (diff)
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Callable, Optional

_LIB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "coding-mastery", "scripts", "_lib")
sys.path.insert(0, _LIB)

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
# commit-URL shapes across hosts; each yields (repo_hint, sha)
_COMMIT_RES = [
    re.compile(r"github\.com/([^/\s]+/[^/\s]+)/commit/([0-9a-f]{7,40})", re.I),
    re.compile(r"gitlab\.com/(.+?)/-/commit/([0-9a-f]{7,40})", re.I),
    re.compile(r"bitbucket\.org/([^/\s]+/[^/\s]+)/commits/([0-9a-f]{7,40})", re.I),
    re.compile(r"(?:cgit|git)\.[^\s]*?[?&]id=([0-9a-f]{12,40})", re.I),   # cgit ?id=<sha> (no repo in url)
]
_GENERIC_COMMIT = re.compile(r"/commit/([0-9a-f]{7,40})", re.I)


def _iter_strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _iter_strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _iter_strings(v)


def parse_commit_url(url: str):
    """Return {host, repo, sha, url} for a recognized commit URL, else None."""
    if not isinstance(url, str):
        return None
    for rx in _COMMIT_RES:
        m = rx.search(url)
        if m:
            if m.re.groups == 2:
                repo, sha = m.group(1), m.group(2)
            else:                                  # cgit: sha only, repo from host/path
                repo, sha = "", m.group(1)
            host = re.sub(r"^https?://", "", url).split("/", 1)[0]
            return {"host": host, "repo": repo.rstrip("/"), "sha": sha.lower(), "url": url}
    m = _GENERIC_COMMIT.search(url)
    if m:
        host = re.sub(r"^https?://", "", url).split("/", 1)[0]
        return {"host": host, "repo": "", "sha": m.group(1).lower(), "url": url}
    return None


def extract_fix_commits(data: dict, source: str = "") -> list:
    """Pull fix commits from any source JSON: every commit URL in any string field, PLUS OSV's
    structured GIT-range `fixed` events (which carry repo + sha without a URL)."""
    found = {}

    def add(host, repo, sha, url):
        key = (repo.lower(), sha.lower())
        if key not in found:
            found[key] = {"host": host, "repo": repo, "sha": sha.lower(), "url": url, "source": source}

    for s in _iter_strings(data):
        pc = parse_commit_url(s)
        if pc:
            add(pc["host"], pc["repo"], pc["sha"], pc["url"])
    # OSV structured ranges
    if isinstance(data, dict):
        for aff in data.get("affected", []) or []:
            if not isinstance(aff, dict):
                continue
            for rng in aff.get("ranges", []) or []:
                if not isinstance(rng, dict) or str(rng.get("type", "")).upper() != "GIT":
                    continue
                repo = str(rng.get("repo", ""))
                host = re.sub(r"^https?://", "", repo).split("/", 1)[0] if repo else ""
                for ev in rng.get("events", []) or []:
                    if isinstance(ev, dict) and re.fullmatch(r"[0-9a-f]{7,40}", str(ev.get("fixed", "")), re.I):
                        add(host, repo, str(ev["fixed"]), repo)
    return list(found.values())


# ------------------------------------------------------------------- sources (fetcher injectable)
def _http_get(url: str, timeout: float = 20) -> Optional[dict]:
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "cve-diff/1.0", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:   # nosec - read-only public advisory APIs
        return json.loads(resp.read().decode("utf-8", "replace"))


SOURCE_URLS = {
    "osv": "https://api.osv.dev/v1/vulns/{cve}",
    "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}",
    "ghsa": "https://api.github.com/advisories?cve_id={cve}",
}


def discover(cve: str, sources=("osv", "nvd", "ghsa"), *, fetcher: Optional[Callable] = None) -> dict:
    """Query each source, merge fix commits de-duplicated by (repo, sha). fetcher(url)->dict|None is
    injectable (default urllib); a source that errors is recorded, not fatal."""
    if not CVE_RE.match(cve or ""):
        raise ValueError(f"not a CVE id: {cve!r}")
    cve = cve.upper()
    get = fetcher or _http_get
    commits, queried, errors = {}, [], {}
    for src in sources:
        url = SOURCE_URLS.get(src)
        if not url:
            continue
        try:
            data = get(url.format(cve=cve))
            queried.append(src)
        except Exception as exc:
            errors[src] = str(exc)
            continue
        if not data:
            continue
        for fc in extract_fix_commits(data, source=src):
            key = (fc["repo"].lower(), fc["sha"])
            if key in commits:
                commits[key].setdefault("also_in", []).append(src)
            else:
                commits[key] = fc
    return {"cve": cve, "fix_commits": list(commits.values()), "count": len(commits),
            "queried": queried, "errors": errors}


# ------------------------------------------------------------------- diff (scope-gated clone)
def fetch_diff(repo_url: str, sha: str, scope_path: str, *, workdir: str = ".cve-diff",
               runner: Optional[Callable] = None) -> dict:
    """Clone (scope-checked + hardened) and emit `git diff sha^..sha`. runner(args_list)->Result
    injectable. Returns {in_scope, diff, error}. Refuses an out-of-scope repo host."""
    import scope_guard
    host = re.sub(r"^https?://", "", repo_url).split("/", 1)[0].split("@")[-1]
    try:
        scope = scope_guard.Scope.load(scope_path)
        decision = scope.evaluate(repo_url)
    except Exception as exc:
        return {"in_scope": False, "diff": "", "error": f"scope check failed: {exc}"}
    if not decision.in_scope:
        return {"in_scope": False, "diff": "", "error": f"repo host {host!r} is out of scope - refusing to clone"}

    import safe_subprocess
    run = runner or (lambda args: safe_subprocess.git_safe(args, timeout=300))
    dest = os.path.join(workdir, re.sub(r"[^A-Za-z0-9_.-]", "_", host + "_" + sha[:12]))
    clone = run(["clone", "--filter=blob:none", "--no-checkout", repo_url, dest])
    if clone is None or getattr(clone, "returncode", 1) != 0:
        return {"in_scope": True, "diff": "",
                "error": f"clone failed: {getattr(clone, 'stderr', 'no runner')[:200]}"}
    diff = run(["-C", dest, "diff", f"{sha}^..{sha}"])
    if diff is None or getattr(diff, "returncode", 1) != 0:
        return {"in_scope": True, "diff": "", "error": f"diff failed: {getattr(diff, 'stderr', '')[:200]}"}
    return {"in_scope": True, "diff": diff.stdout, "error": ""}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Find + diff the canonical fix commit(s) for a CVE.")
    sub = p.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("find"); f.add_argument("cve")
    f.add_argument("--source", default="osv,nvd,ghsa"); f.add_argument("--json")
    d = sub.add_parser("diff"); d.add_argument("cve"); d.add_argument("--repo", required=True)
    d.add_argument("--sha", required=True); d.add_argument("--scope", required=True)
    d.add_argument("--workdir", default=".cve-diff")
    args = p.parse_args(argv)
    try:
        if args.cmd == "find":
            srcs = tuple(s.strip() for s in args.source.split(",") if s.strip())
            res = discover(args.cve, sources=srcs)
            if args.json:
                with open(args.json, "w", encoding="utf-8") as fh:
                    json.dump(res, fh, indent=2)
            for fc in res["fix_commits"]:
                print(f"{fc['sha'][:12]}  {fc.get('repo') or fc.get('host'):40}  [{fc.get('source')}]")
            print(f"\n[+] {res['count']} fix commit(s) for {res['cve']}; queried={res['queried']}"
                  + (f"; errors={res['errors']}" if res["errors"] else ""))
            return 0
        if args.cmd == "diff":
            res = fetch_diff(args.repo, args.sha, args.scope, workdir=args.workdir)
            if res.get("error"):
                print(f"error: {res['error']}", file=sys.stderr)
                return 3 if not res.get("in_scope") else 2
            sys.stdout.write(res["diff"])
            return 0
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
