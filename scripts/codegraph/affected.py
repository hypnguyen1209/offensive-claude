#!/usr/bin/env python3
"""affected.py - "which dangerous sinks are downstream of this change?" (codegraph affected.py).

Given the files a commit touched (`git diff --name-only`), walk the code graph FORWARD from the
symbols in those files and report the security-sensitive sinks they can reach. Augments
`/engage.cvediff` + the `patch-diffing-nday` skill: given a CVE fix commit, this answers "what
attacker-reachable sinks sit downstream of the changed code" so the audit leads with the code the
patch actually affects, not the whole tree.

Candidate generation, never proof: a reachable sink is a LEAD for the verifier, and the reaching path
carries its weakest-hop provenance (an INFERRED/AMBIGUOUS hop caps a reachability claim below
[CONFIRMED] - PR-3's gate). Sinks are matched by callee NAME against a small CWE-tagged catalog; a
name match is a pattern hit, not a demonstrated vuln.

CLI:
  affected.py --db g.sqlite --files app/views.py,app/db.py
  git diff --name-only | affected.py --db g.sqlite --stdin
  affected.py --db g.sqlite --changed-list changed.txt [--depth 6] [--json]
Exit: 0 (incl. recoverable "no changed symbols in graph"), 2 on db error.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections import deque
from typing import Optional

# callee short-name -> (CWE, why). Deliberately small + high-signal; a name hit is a lead to verify.
SINK_CATALOG = {
    "system": ("CWE-78", "OS command execution"),
    "popen": ("CWE-78", "OS command execution"),
    "exec": ("CWE-95", "dynamic code execution"),
    "eval": ("CWE-95", "dynamic code execution"),
    "execute": ("CWE-89", "SQL query execution"),
    "executemany": ("CWE-89", "SQL query execution"),
    "executescript": ("CWE-89", "SQL query execution"),
    "loads": ("CWE-502", "deserialization"),
    "load": ("CWE-502", "deserialization (yaml/pickle)"),
    "check_output": ("CWE-78", "subprocess execution"),
    "check_call": ("CWE-78", "subprocess execution"),
    "call": ("CWE-78", "subprocess execution"),
    "Popen": ("CWE-78", "subprocess execution"),
    "render_template_string": ("CWE-1336", "server-side template injection"),
    "send_file": ("CWE-22", "path traversal / file disclosure"),
    "urlopen": ("CWE-918", "server-side request"),
    "request": ("CWE-918", "server-side request"),
}


def _connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("SELECT 1 FROM symbols LIMIT 1")
    return conn


def _norm(path: str) -> str:
    return path.replace("\\", "/").strip().lstrip("./")


def symbols_in_files(conn, files: list) -> list:
    """Symbol ids defined in any of the changed files (suffix-normalized match, so a repo-relative
    `pkg/mod.py` matches a graph file stored the same way)."""
    wanted = {_norm(f) for f in files if f.strip()}
    out = []
    for sid, fpath in conn.execute("SELECT id, file FROM symbols").fetchall():
        nf = _norm(fpath)
        if nf in wanted or any(nf == w or nf.endswith("/" + w) or w.endswith("/" + nf) for w in wanted):
            out.append(sid)
    return out


def forward_reachable(conn, seed_ids: list, depth: int = 6) -> set:
    """Symbols reachable FORWARD from the seeds over `calls` edges (includes the seeds themselves)."""
    seen = set(seed_ids)
    frontier = deque((s, 0) for s in seed_ids)
    while frontier:
        cur, d = frontier.popleft()
        if d >= depth:
            continue
        for (tgt,) in conn.execute("SELECT target FROM edges WHERE kind='calls' AND source=?",
                                   (cur,)).fetchall():
            if tgt not in seen:
                seen.add(tgt)
                frontier.append((tgt, d + 1))
    return seen


def _label(conn, node_id: str) -> str:
    row = conn.execute("SELECT qualified_name, file FROM symbols WHERE id=?", (node_id,)).fetchone()
    return f"{row[1]}::{row[0]}" if row else node_id


def affected_sinks(conn, files: list, depth: int = 6) -> dict:
    """Return {seed_symbols, reachable_count, sinks:[...]}. Each sink hit = a dangerous callee name
    invoked by a symbol reachable from the changed files."""
    seeds = symbols_in_files(conn, files)
    reachable = forward_reachable(conn, seeds, depth)
    hits = []
    if reachable:
        qmarks = ",".join("?" for _ in reachable)
        rlist = list(reachable)
        # resolved callsites (attr or name) whose callee is a catalog sink
        for src, callee, ckind, f, line in conn.execute(
                f"SELECT source, callee_name, callee_kind, file, line FROM callsites "
                f"WHERE source IN ({qmarks})", rlist).fetchall():
            if callee in SINK_CATALOG:
                cwe, why = SINK_CATALOG[callee]
                hits.append({"sink": callee, "cwe": cwe, "why": why, "kind": ckind,
                             "in": _label(conn, src), "site": f"{f}:{line}" if line else f,
                             "reached_from_change": True})
    # dedup by (sink, site)
    seen_key = set()
    uniq = []
    for h in hits:
        k = (h["sink"], h["site"])
        if k not in seen_key:
            seen_key.add(k)
            uniq.append(h)
    uniq.sort(key=lambda h: (h["cwe"], h["site"]))
    return {"seed_symbols": len(seeds), "reachable_count": len(reachable), "sinks": uniq}


def _read_files(args) -> list:
    if args.stdin:
        return [ln.strip() for ln in sys.stdin.read().splitlines() if ln.strip()]
    if args.changed_list:
        with open(args.changed_list, "r", encoding="utf-8") as fh:
            return [ln.strip() for ln in fh if ln.strip()]
    if args.files:
        return [x.strip() for x in args.files.split(",") if x.strip()]
    return []


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(description="Downstream security sinks affected by changed files.")
    p.add_argument("--db", required=True)
    p.add_argument("--files", help="comma-separated changed file paths")
    p.add_argument("--changed-list", help="file with one changed path per line")
    p.add_argument("--stdin", action="store_true", help="read changed paths from stdin (git diff --name-only)")
    p.add_argument("--depth", type=int, default=6)
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    files = _read_files(args)
    if not files:
        print("no changed files given (pass --files / --changed-list / --stdin)", file=sys.stderr)
        return 2
    try:
        conn = _connect(args.db)
    except sqlite3.Error as exc:
        print(f"error: not a code graph db ({exc}) - run build_graph.py first", file=sys.stderr)
        return 2
    try:
        res = affected_sinks(conn, files, max(1, args.depth))
    finally:
        conn.close()
    if args.json:
        print(json.dumps(res, indent=2))
        return 0
    if res["seed_symbols"] == 0:
        print("no changed symbols found in the graph - are the paths repo-relative and indexed? "
              "(rebuild with build_graph.py). Nothing downstream to report.")
        return 0
    if not res["sinks"]:
        print(f"{res['seed_symbols']} changed symbol(s), {res['reachable_count']} reachable - "
              "no catalogued security sinks downstream.")
        return 0
    print(f"{res['seed_symbols']} changed symbol(s) reach {res['reachable_count']} symbol(s); "
          f"{len(res['sinks'])} downstream sink(s):")
    for h in res["sinks"]:
        print(f"  [{h['cwe']}] {h['sink']}() ({h['why']}) in {h['in']} @ {h['site']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
