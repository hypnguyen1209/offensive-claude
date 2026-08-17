#!/usr/bin/env python3
"""attack_surface.py - subsystems, choke points, and trust-boundary crossings from the graph (codegraph).

Turns the raw call graph into an attack-surface map to seed `threat-model-discipline` + surface
mapping. All findings are candidate generation - a choke point is a place to LOOK, not a vuln.

Four views, all DETERMINISTIC (no Leiden/Louvain dependency - graphify uses graspologic; we use a
reproducible package-zone + connected-components fallback so two runs give the same map):

  * trust zones     - symbols grouped by top-level package/dir (the deterministic community proxy).
  * subsystems      - connected components over undirected `calls` edges (islands of code).
  * god-nodes       - highest-degree choke points (high fan-in/out): a bug here has wide blast radius,
                      and a shared sink here is a high-value target. Generated/vendored symbols are
                      DEMOTED (codegraph) so the map leads with hand-written code.
  * surprising      - `calls` edges that CROSS a trust zone (source zone != target zone). A cross-zone
    connections       call is a trust-boundary crossing - exactly where unvalidated data changes
                      hands. Weakest-provenance crossings into god-nodes/sinks auto-seed the worklist.

CLI:
  attack_surface.py --db g.sqlite [--top 15] [--json]
Exit: 0 (incl. recoverable empty-graph guidance), 2 on db error.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from typing import Optional

# reuse affected.py's CWE-tagged sink catalog so the worklist agrees on "what is a sink"
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
import affected as af  # noqa: E402

_PROV_RANK = {"AMBIGUOUS": 0, "INFERRED": 1, "EXTRACTED": 2}


def _connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("SELECT 1 FROM symbols LIMIT 1")
    return conn


def _zone_of(fpath: str) -> str:
    """Trust zone = first path segment (package/dir), or '<root>' for a top-level file."""
    norm = fpath.replace("\\", "/").lstrip("./")
    return norm.split("/", 1)[0] if "/" in norm else "<root>"


def _symbol_index(conn) -> dict:
    idx = {}
    for sid, qn, fpath, gen in conn.execute("SELECT id, qualified_name, file, generated FROM symbols"):
        idx[sid] = {"qn": qn, "file": fpath, "zone": _zone_of(fpath), "generated": gen,
                    "label": f"{fpath}::{qn}"}
    return idx


def trust_zones(conn) -> dict:
    idx = _symbol_index(conn)
    zones: dict = {}
    for sid, info in idx.items():
        zones.setdefault(info["zone"], 0)
        zones[info["zone"]] += 1
    return dict(sorted(zones.items(), key=lambda kv: (-kv[1], kv[0])))


def connected_components(conn) -> list:
    """Union-find over undirected `calls` edges -> list of component sizes (subsystem islands)."""
    parent: dict = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[min(ra, rb)] = max(ra, rb)

    for sid, in conn.execute("SELECT id FROM symbols"):
        find(sid)
    for s, t in conn.execute("SELECT source, target FROM edges WHERE kind='calls'"):
        union(s, t)
    comps: dict = {}
    for node in list(parent):
        comps.setdefault(find(node), set()).add(node)
    return sorted((len(c) for c in comps.values()), reverse=True)


def god_nodes(conn, top_n: int = 15) -> list:
    """Highest-degree choke points (fan-in + fan-out over `calls`). Generated symbols demoted."""
    idx = _symbol_index(conn)
    deg: dict = {sid: 0 for sid in idx}
    for s, t in conn.execute("SELECT source, target FROM edges WHERE kind='calls'"):
        if s in deg:
            deg[s] += 1
        if t in deg:
            deg[t] += 1
    ranked = []
    for sid, d in deg.items():
        if d == 0:
            continue
        info = idx[sid]
        # demotion: generated symbols sort after hand-written ones at equal degree, via a penalty key
        ranked.append({"id": sid, "label": info["label"], "zone": info["zone"], "degree": d,
                       "generated": info["generated"]})
    ranked.sort(key=lambda r: (r["generated"], -r["degree"], r["label"]))
    return ranked[:top_n]


def surprising_connections(conn) -> list:
    """`calls` edges whose source and target live in DIFFERENT trust zones (boundary crossings)."""
    idx = _symbol_index(conn)
    out = []
    for s, t, prov, f, line in conn.execute(
            "SELECT source, target, provenance, file, line FROM edges WHERE kind='calls'"):
        si, ti = idx.get(s), idx.get(t)
        if not si or not ti or si["zone"] == ti["zone"]:
            continue
        out.append({"from": si["label"], "to": ti["label"], "from_id": s, "to_id": t,
                    "from_zone": si["zone"], "to_zone": ti["zone"], "provenance": prov,
                    "site": f"{f}:{line}" if line else f})
    # weakest provenance first (least-certain crossings deserve the most scrutiny)
    out.sort(key=lambda c: (_PROV_RANK.get(c["provenance"], 0), c["from_zone"], c["to_zone"]))
    return out


def worklist(conn, top_n: int = 15) -> list:
    """Auto-seeded validation worklist: cross-zone crossings that land on a god-node or a sink."""
    gods = {g["id"] for g in god_nodes(conn, top_n)}
    # symbols that invoke a catalogued sink (keyed by the invoking symbol id)
    sink_syms = {}
    for src, callee, f, line in conn.execute(
            "SELECT source, callee_name, file, line FROM callsites"):
        if callee in af.SINK_CATALOG:
            sink_syms.setdefault(src, (callee, f, line))
    items = []
    for c in surprising_connections(conn):
        tid = c["to_id"]                            # threaded through - no fragile label re-matching
        reasons = []
        if tid in gods:
            reasons.append("crosses into a god-node (wide blast radius)")
        if tid in sink_syms:
            callee, _sf, _sl = sink_syms[tid]
            cwe, why = af.SINK_CATALOG[callee]
            reasons.append(f"target invokes {callee}() [{cwe}: {why}]")
        if reasons:
            items.append({**c, "why": reasons})
    items.sort(key=lambda i: (_PROV_RANK.get(i["provenance"], 0), i["from_zone"]))
    return items[:top_n]


def build_map(conn, top_n: int = 15) -> dict:
    return {"trust_zones": trust_zones(conn),
            "subsystem_sizes": connected_components(conn),
            "god_nodes": god_nodes(conn, top_n),
            "surprising_connections": surprising_connections(conn)[:top_n],
            "worklist": worklist(conn, top_n)}


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(description="Attack-surface map from the code graph.")
    p.add_argument("--db", required=True)
    p.add_argument("--top", type=int, default=15)
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    try:
        conn = _connect(args.db)
    except sqlite3.Error as exc:
        print(f"error: not a code graph db ({exc}) - run build_graph.py first", file=sys.stderr)
        return 2
    try:
        n = conn.execute("SELECT COUNT(*) FROM symbols").fetchone()[0]
        if n == 0:
            print("empty graph - nothing to map. Build one with build_graph.py first.")
            return 0
        m = build_map(conn, max(1, args.top))
    finally:
        conn.close()
    if args.json:
        print(json.dumps(m, indent=2))
        return 0
    print(f"trust zones: {', '.join(f'{z}({c})' for z, c in list(m['trust_zones'].items())[:10])}")
    print(f"subsystems (sizes): {m['subsystem_sizes'][:10]}")
    print("god-nodes (choke points):")
    for g in m["god_nodes"]:
        tag = " [generated]" if g["generated"] else ""
        print(f"  deg={g['degree']:>3}  {g['label']}{tag}")
    print(f"surprising connections (trust-boundary crossings): {len(m['surprising_connections'])}")
    for c in m["surprising_connections"][:10]:
        print(f"  [{c['provenance']}] {c['from_zone']} -> {c['to_zone']}: "
              f"{c['from']} -> {c['to']} @ {c['site']}")
    if m["worklist"]:
        print("validation worklist (auto-seeded):")
        for w in m["worklist"]:
            print(f"  {w['from_zone']} -> {w['to_zone']}  {w['to']}  ({'; '.join(w['why'])})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
