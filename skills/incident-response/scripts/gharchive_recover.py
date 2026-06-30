#!/usr/bin/env python3
"""gharchive_recover.py - build recovery queries for deleted PRs / issues / force-pushed history.

An attacker who deletes a PR or force-pushes to hide a malicious change cannot scrub the EXTERNAL,
immutable mirrors of GitHub activity. This builds the queries/URLs for three independent recovery
sources (a fourth, dangling commits, is `dangling_commit_finder.py`):

  1. GitHub Events API   - free, recent (last ~90 events) repo activity (api.github.com/repos/R/events)
  2. GH Archive          - free hourly public-event dumps at data.gharchive.org (PushEvent/Pull/Issues)
  3. Wayback Machine CDX  - archived snapshots of PR/issue pages that were later deleted

BigQuery over GH Archive is the heavyweight option and is INTENTIONALLY optional (the SQL is emitted
for the operator to run if needed) - the free Events API + Wayback + git fsck cover most cases without
any cloud credentials. This script only BUILDS the queries (pure stdlib, offline & testable); actually
fetching is the operator's explicit, scoped step.

CLI:
  gharchive_recover.py plan owner/repo [--from 2026-06-01 --to 2026-06-30] [--json out.json]
  gharchive_recover.py events owner/repo            # build only the free Events API URL
"""
from __future__ import annotations

import argparse
import json
import re
import sys

REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def _check_repo(repo: str) -> str:
    # fullmatch (not match): `match` + `$` would accept a trailing newline ("o/r\n"), enabling
    # CRLF/newline injection into the built URLs / CDX queries / SQL.
    if not isinstance(repo, str) or not REPO_RE.fullmatch(repo):
        raise ValueError(f"repo must be 'owner/name' (no whitespace/newline), got {repo!r}")
    owner, name = repo.split("/", 1)
    if owner.strip(".") == "" or name.strip(".") == "":   # reject '.'/'..' traversal-style components
        raise ValueError(f"invalid repo component (dot-only) in {repo!r}")
    return repo


def _check_date(d: str) -> "object":
    from datetime import date
    # [0-9] (not \d, which also matches Unicode digits like fullwidth '４') so a non-ASCII-digit
    # string can't pass the gate and then be interpolated raw into a URL/SQL.
    m = re.fullmatch(r"([0-9]{4})-([0-9]{2})-([0-9]{2})", d or "")
    if not m:
        raise ValueError(f"date must be ASCII YYYY-MM-DD, got {d!r}")
    return date(int(m.group(1)), int(m.group(2)), int(m.group(3)))


def github_events_url(repo: str) -> str:
    return f"https://api.github.com/repos/{_check_repo(repo)}/events?per_page=100"


def wayback_cdx_urls(repo: str) -> dict:
    """CDX queries for archived PR / issue / commit pages (recovers deleted ones)."""
    r = _check_repo(repo)
    base = "https://web.archive.org/cdx/search/cdx?output=json&collapse=urlkey&url="
    return {
        "pulls": base + f"github.com/{r}/pull*",
        "issues": base + f"github.com/{r}/issues*",
        "commits": base + f"github.com/{r}/commit*",
    }


def gharchive_http_hours(date_from: str, date_to: str) -> list:
    """Hourly GH Archive file URLs across [date_from, date_to] (inclusive, YYYY-MM-DD).
    Caps the span so a fat-fingered range can't generate millions of URLs."""
    from datetime import date
    a, b = _check_date(date_from), _check_date(date_to)
    if b < a:
        raise ValueError("--to is before --from")
    if (b - a).days > 31:
        raise ValueError("range exceeds 31 days - narrow it (GH Archive is 1 file/hour)")
    urls, d = [], a
    while d <= b:
        for h in range(24):
            urls.append(f"https://data.gharchive.org/{d.isoformat()}-{h}.json.gz")
        d = date.fromordinal(d.toordinal() + 1)
    return urls


def gharchive_bigquery_sql(repo: str, date_from: str, date_to: str) -> str:
    """OPTIONAL BigQuery SQL (githubarchive.day.*). Operator runs it only if the free sources miss."""
    r = _check_repo(repo)
    df = _check_date(date_from); dt = _check_date(date_to)   # NORMALIZE; never interpolate raw input
    suffix_from, suffix_to = df.isoformat().replace("-", ""), dt.isoformat().replace("-", "")
    return (
        "-- OPTIONAL: requires a GCP project + BigQuery; the free Events API/Wayback usually suffice.\n"
        "SELECT created_at, type, actor.login, JSON_EXTRACT_SCALAR(payload, '$.ref') AS ref,\n"
        "       JSON_EXTRACT_SCALAR(payload, '$.before') AS before_sha,\n"
        "       JSON_EXTRACT_SCALAR(payload, '$.head') AS head_sha\n"
        "FROM `githubarchive.day.*`\n"
        f"WHERE _TABLE_SUFFIX BETWEEN '{suffix_from}' AND '{suffix_to}'\n"
        f"  AND repo.name = '{r}'\n"
        "  AND type IN ('PushEvent','PullRequestEvent','IssuesEvent','DeleteEvent')\n"
        "ORDER BY created_at;"
    )


def recovery_plan(repo: str, date_from: str = "", date_to: str = "") -> dict:
    r = _check_repo(repo)
    plan = {
        "repo": r,
        "sources": {
            "github_events_api": {"url": github_events_url(r), "note": "free; recent events only (~90)"},
            "wayback_cdx": {"queries": wayback_cdx_urls(r), "note": "archived deleted PR/issue/commit pages"},
            "gharchive_http": {"note": "free hourly dumps; provide --from/--to to list file URLs"},
        },
        "optional": {"gharchive_bigquery": {"note": "needs GCP; only if the free sources miss"}},
        "also_run": "dangling_commit_finder.py (the 4th, immutable source: force-pushed commits)",
    }
    if date_from and date_to:
        plan["sources"]["gharchive_http"]["files"] = gharchive_http_hours(date_from, date_to)
        plan["optional"]["gharchive_bigquery"]["sql"] = gharchive_bigquery_sql(r, date_from, date_to)
    return plan


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Build recovery queries for deleted/force-pushed GitHub activity.")
    sub = p.add_subparsers(dest="cmd", required=True)
    pl = sub.add_parser("plan"); pl.add_argument("repo")
    pl.add_argument("--from", dest="dfrom", default=""); pl.add_argument("--to", dest="dto", default="")
    pl.add_argument("--json")
    ev = sub.add_parser("events"); ev.add_argument("repo")
    args = p.parse_args(argv)
    try:
        if args.cmd == "events":
            print(github_events_url(args.repo))
            return 0
        plan = recovery_plan(args.repo, args.dfrom, args.dto)
        if args.json:
            with open(args.json, "w", encoding="utf-8") as fh:
                json.dump(plan, fh, indent=2)
        print(json.dumps(plan, indent=2))
        return 0
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
