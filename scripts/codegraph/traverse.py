#!/usr/bin/env python3
"""traverse.py - walk the code graph for variant hunting and source-to-sink tracing (graphify).

Reads a graph built by `build_graph.py` and answers three questions, all candidate-generation for the
verification pipeline - never proof:

  callers  <symbol>          direct callers (reverse of `calls` edges) - who reaches this sink?
  impact   <symbol> [depth]  reverse-reachability set (impact radius / blast radius) for VARIANT
                             HUNTING - excludes `contains` edges so a class doesn't drag in every
                             sibling method and explode the frontier.
  path     <src> <sink>      shortest DIRECTED call path source->sink, printing PER-HOP relation +
                             provenance + the call SITE (file:line of the edge, not the def line -
                             graphify: cite where the call happens). The path's strength is its
                             WEAKEST hop (EXTRACTED > INFERRED > AMBIGUOUS) - this is exactly what
                             feeds PR-3's per-hop provenance gate: any INFERRED/AMBIGUOUS hop caps a
                             reachability claim below [CONFIRMED].

Directed by default (graphify caveat: taint has direction - a caller reaching a sink is NOT the same
as the sink reaching the caller). Pure stdlib.

CLI:
  traverse.py callers --db g.sqlite --symbol execute_query
  traverse.py impact  --db g.sqlite --symbol parse_input --depth 4
  traverse.py path    --db g.sqlite --from handle_request --to os_system [--json]
Exit: 0 (incl. recoverable not-found / no-path guidance), 2 on a genuine db error.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections import deque
from typing import Optional

_PROV_RANK = {"AMBIGUOUS": 0, "INFERRED": 1, "EXTRACTED": 2}


def _connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("SELECT 1 FROM symbols LIMIT 1")   # fail fast on a non-graph db
    return conn


def resolve_symbols(conn, ident: str) -> list:
    """Resolve an identifier (node id, qualified name, or bare name) to (id, qualified_name, file)."""
    rows = conn.execute("SELECT id, qualified_name, file FROM symbols WHERE id=?", (ident,)).fetchall()
    if rows:
        return rows
    rows = conn.execute("SELECT id, qualified_name, file FROM symbols WHERE qualified_name=?",
                        (ident,)).fetchall()
    if rows:
        return rows
    return conn.execute("SELECT id, qualified_name, file FROM symbols WHERE name=?", (ident,)).fetchall()


def _label(conn, node_id: str) -> str:
    row = conn.execute("SELECT qualified_name, file FROM symbols WHERE id=?", (node_id,)).fetchone()
    return f"{row[1]}::{row[0]}" if row else node_id


def callers(conn, node_id: str) -> list:
    """Direct callers: rows (source_id, provenance, file, line) with a `calls` edge into node_id."""
    return conn.execute(
        "SELECT source, provenance, file, line FROM edges WHERE kind='calls' AND target=?",
        (node_id,)).fetchall()


def impact_radius(conn, node_id: str, depth: int = 3) -> list:
    """Reverse-reachable callers within `depth` hops (BFS on reversed `calls` edges, no `contains`)."""
    seen = {node_id}
    frontier = deque([(node_id, 0)])
    out = []
    while frontier:
        cur, d = frontier.popleft()
        if d >= depth:
            continue
        for src, prov, _f, _l in callers(conn, cur):
            if src not in seen:
                seen.add(src)
                out.append({"id": src, "label": _label(conn, src), "distance": d + 1,
                            "provenance": prov})
                frontier.append((src, d + 1))
    return out


def shortest_path(conn, src_id: str, sink_id: str) -> Optional[list]:
    """Shortest DIRECTED call path src->sink. Returns a list of hop dicts, or None if unreachable."""
    if src_id == sink_id:
        return []
    # BFS over directed `calls` edges, remembering the edge used to arrive.
    prev: dict = {src_id: None}
    q = deque([src_id])
    while q:
        cur = q.popleft()
        if cur == sink_id:
            break
        for tgt, prov, fpath, line in conn.execute(
                "SELECT target, provenance, file, line FROM edges WHERE kind='calls' AND source=?",
                (cur,)).fetchall():
            if tgt not in prev:
                prev[tgt] = (cur, prov, fpath, line)
                q.append(tgt)
    if sink_id not in prev:
        return None
    # reconstruct
    hops = []
    node = sink_id
    while prev[node] is not None:
        parent, prov, fpath, line = prev[node]
        hops.append({"from": _label(conn, parent), "to": _label(conn, node),
                     "relation": "calls", "provenance": prov,
                     "site": f"{fpath}:{line}" if line else fpath})
        node = parent
    hops.reverse()
    return hops


def path_strength(hops: list) -> str:
    """A path is only as strong as its weakest hop (empty path = trivially EXTRACTED: same node)."""
    if not hops:
        return "EXTRACTED"
    return min((h.get("provenance", "AMBIGUOUS") for h in hops), key=lambda p: _PROV_RANK.get(p, 0))


def _one(conn, ident: str, role: str):
    """Resolve to exactly one symbol id, or print recoverable guidance and return None."""
    cands = resolve_symbols(conn, ident)
    if not cands:
        print(f"{role} {ident!r} not found in the graph - check the name or rebuild "
              "(build_graph.py). Nothing to trace.")
        return None
    if len(cands) > 1:
        print(f"{role} {ident!r} is ambiguous ({len(cands)} matches); disambiguate with a qualified "
              f"name or node id:")
        for cid, qn, f in cands[:20]:
            print(f"  {cid}  {f}::{qn}")
        return None
    return cands[0][0]


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(description="Traverse the code graph (callers / impact / path).")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("callers"); c.add_argument("--db", required=True)
    c.add_argument("--symbol", required=True); c.add_argument("--json", action="store_true")
    im = sub.add_parser("impact"); im.add_argument("--db", required=True)
    im.add_argument("--symbol", required=True); im.add_argument("--depth", type=int, default=3)
    im.add_argument("--json", action="store_true")
    pa = sub.add_parser("path"); pa.add_argument("--db", required=True)
    pa.add_argument("--from", dest="src", required=True); pa.add_argument("--to", dest="sink", required=True)
    pa.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    try:
        conn = _connect(args.db)
    except sqlite3.Error as exc:
        print(f"error: not a code graph db ({exc}) - run build_graph.py first", file=sys.stderr)
        return 2
    try:
        if args.cmd == "callers":
            nid = _one(conn, args.symbol, "symbol")
            if nid is None:
                return 0
            rows = [{"caller": _label(conn, s), "provenance": prov, "site": f"{f}:{l}" if l else f}
                    for s, prov, f, l in callers(conn, nid)]
            print(json.dumps(rows, indent=2) if args.json else
                  ("\n".join(f"  {r['caller']}  [{r['provenance']}] @ {r['site']}" for r in rows)
                   or "no direct callers (this may be an entry point or dead code)"))
            return 0
        if args.cmd == "impact":
            nid = _one(conn, args.symbol, "symbol")
            if nid is None:
                return 0
            rows = impact_radius(conn, nid, max(1, args.depth))
            print(json.dumps(rows, indent=2) if args.json else
                  ("\n".join(f"  d{r['distance']} {r['label']}  [{r['provenance']}]" for r in rows)
                   or "no upstream callers within depth"))
            return 0
        if args.cmd == "path":
            s = _one(conn, args.src, "source")
            t = _one(conn, args.sink, "sink")
            if s is None or t is None:
                return 0
            hops = shortest_path(conn, s, t)
            if hops is None:
                print(f"no directed call path {args.src} -> {args.sink} (not reachable in the graph; "
                      "remember AMBIGUOUS/unresolved indirect calls are not edges)")
                return 0
            strength = path_strength(hops)
            if args.json:
                print(json.dumps({"strength": strength, "hops": hops}, indent=2))
            else:
                print(f"path strength (weakest hop): {strength}")
                for h in hops:
                    print(f"  {h['from']} -> {h['to']}  [{h['provenance']}] @ {h['site']}")
                if strength != "EXTRACTED":
                    print(f"  note: a {strength} hop caps any reachability claim below [CONFIRMED] "
                          "(PR-3 provenance gate)")
            return 0
    finally:
        conn.close()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
