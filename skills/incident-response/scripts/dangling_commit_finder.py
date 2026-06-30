#!/usr/bin/env python3
"""dangling_commit_finder.py - recover hidden/force-pushed commits from a compromised repo.

When an attacker force-pushes to erase a malicious commit, the commit object usually survives as a
DANGLING / UNREACHABLE object - "forensic gold" for a repo-compromise post-mortem (the aws-toolkit
-style investigation). This walks a LOCAL clone with `git fsck` + reflog and reports every commit
that is no longer reachable from a ref, with its author/date/subject so an investigator can spot the
injected change. One of four independent evidence sources in `references/repo-compromise-forensics.md`.

ALL git runs go through `safe_subprocess.git_safe` (hooks/prompt/host-config/ext-transport/symlinks
disabled): the repo under investigation is UNTRUSTED. Read-only - never writes to the repo. Degrades
gracefully if git is missing (returns an empty report with a note, exit 0).

Pure stdlib. CLI:
  dangling_commit_finder.py find <repo> [--json out.json] [--no-reflogs]
  exit 0 ok (even with findings), 2 error
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "..", "coding-mastery", "scripts", "_lib"))
try:
    import safe_subprocess
except Exception:  # pragma: no cover - safe_subprocess always present in-repo
    safe_subprocess = None

_OBJ = re.compile(r"^(?:dangling|unreachable|missing)\s+commit\s+([0-9a-f]{7,40})", re.I)


def _git(repo: str, args: list, timeout: float = 60):
    """Run a hardened git command in `repo`. Returns a Result, or None if git is unavailable."""
    if safe_subprocess is None:
        return None
    return safe_subprocess.git_safe(["-C", repo, *args], timeout=timeout)


def fsck_unreachable(repo: str, no_reflogs: bool = True) -> list:
    """SHAs of commits unreachable from any ref (the force-push survivors)."""
    args = ["fsck", "--full", "--unreachable", "--dangling"]
    if no_reflogs:
        args.append("--no-reflogs")   # treat reflog entries as non-roots -> surface hidden commits
    res = _git(repo, args)
    if res is None or res.timed_out:
        return []
    shas = []
    for line in (res.stdout + "\n" + res.stderr).splitlines():
        m = _OBJ.match(line.strip())
        if m:
            shas.append(m.group(1))
    return sorted(set(shas))


_BADCHARS = re.compile(  # control + Unicode bidi/zero-width/separator (terminal-spoofing) chars
    "[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u206f\u2028\u2029\ufeff]")


def _clean(s: str) -> str:
    """Neutralize control + Unicode bidi/zero-width/separator chars from an UNTRUSTED repo string
    (commit author/subject) before it lands in a report or terminal - blocks \\x1f field-separator
    confusion, ANSI escapes, CR/LF log injection, and U+202E/zero-width terminal spoofing. Renders
    each as a visible \\xNN (<=0xff) or \\uNNNN escape."""
    def esc(m):
        cp = ord(m.group())
        return f"\\x{cp:02x}" if cp <= 0xff else f"\\u{cp:04x}"
    return _BADCHARS.sub(esc, s or "")


def commit_meta(repo: str, sha: str) -> dict:
    # Read each field in a SEPARATE git invocation so an attacker-controlled %an/%s (which may embed
    # any byte) can never bleed into the date/subject of a single delimited line (forensic forgery).
    def field(fmt: str) -> str:
        r = _git(repo, ["show", "-s", f"--format={fmt}", sha])
        return r.stdout.strip() if (r is not None and r.ok) else ""
    h = field("%H")
    subject = _clean(field("%s"))[:200]
    return {"sha": (h or sha)[:40],
            "author": _clean(field("%an"))[:120],
            "date": _clean(field("%aI"))[:40],
            "subject": subject or "(unreadable)"}


def reflog_rewrites(repo: str) -> list:
    """Reflog lines that indicate history rewriting (reset/rebase/amend/force) - rewrite evidence."""
    res = _git(repo, ["reflog", "--all", "--format=%gd %gs"])
    if res is None or not res.ok:
        return []
    out = []
    for line in res.stdout.splitlines():
        low = line.lower()
        if any(k in low for k in ("reset:", "rebase", "amend", "filter-repo", "filter-branch", "forced-update")):
            out.append(line.strip()[:200])
    return out


def analyze(repo: str, no_reflogs: bool = True) -> dict:
    if not os.path.isdir(os.path.join(repo, ".git")) and not os.path.isfile(os.path.join(repo, "HEAD")):
        # accept a worktree (.git dir) or a bare repo (HEAD at top); otherwise note it
        note_not_repo = not os.path.isdir(repo)
    else:
        note_not_repo = False
    shas = fsck_unreachable(repo, no_reflogs=no_reflogs)
    commits = [commit_meta(repo, s) for s in shas]
    rewrites = reflog_rewrites(repo)
    note = ""
    if safe_subprocess is None:
        note = "safe_subprocess unavailable"
    elif _git(repo, ["rev-parse", "--git-dir"]) is None:
        note = "git unavailable - install git to recover dangling commits"
    elif note_not_repo:
        note = f"{repo} is not a directory"
    return {
        "repo": repo,
        "dangling_commits": commits,
        "dangling_count": len(commits),
        "reflog_rewrites": rewrites,
        "note": note,
        "hint": "review each dangling commit's diff (git show <sha>) for an injected change that was "
                "force-pushed away; corroborate with GH-Archive / Wayback (repo-compromise-forensics.md)",
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Recover hidden/force-pushed commits from a repo clone.")
    p.add_argument("repo")
    p.add_argument("--json")
    p.add_argument("--keep-reflogs", action="store_true",
                   help="count reflog entries as roots (fewer dangling; default treats them as non-roots)")
    args = p.parse_args(argv)
    try:
        report = analyze(args.repo, no_reflogs=not args.keep_reflogs)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"[+] {report['dangling_count']} dangling commit(s) -> {args.json}", file=sys.stderr)
    else:
        for c in report["dangling_commits"]:
            print(f"{c['sha'][:12]}  {c['date']:25}  {c['author'][:24]:24}  {c['subject'][:60]}")
        if report["reflog_rewrites"]:
            print(f"\n[reflog rewrites] {len(report['reflog_rewrites'])} entr(ies):")
            for r in report["reflog_rewrites"][:10]:
                print("  " + r)
        print(f"\n[+] {report['dangling_count']} dangling commit(s)"
              + (f"; note: {report['note']}" if report["note"] else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
