"""Tests for traverse.py - callers / impact radius / source-to-sink path."""
import sqlite3
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts" / "codegraph"
sys.path.insert(0, str(_SCRIPTS))

import build_graph as bg  # noqa: E402
import traverse as tv  # noqa: E402


def _graph(tmp_path, files):
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    db = str(tmp_path / "g.sqlite")
    bg.build(str(tmp_path), db)
    return db


# a small chain: handle -> validate -> run_query (sink)
_CHAIN = {"app.py": (
    "def handle():\n    validate()\n"
    "def validate():\n    run_query()\n"
    "def run_query():\n    pass\n"
    "def other():\n    run_query()\n"
)}


def test_callers_finds_direct_callers(tmp_path):
    db = _graph(tmp_path, _CHAIN)
    conn = sqlite3.connect(db)
    rq = tv.resolve_symbols(conn, "run_query")[0][0]
    callers = tv.callers(conn, rq)
    caller_labels = {tv._label(conn, c[0]) for c in callers}
    conn.close()
    assert any("validate" in x for x in caller_labels)
    assert any("other" in x for x in caller_labels)


def test_impact_radius_is_reverse_reachable(tmp_path):
    db = _graph(tmp_path, _CHAIN)
    conn = sqlite3.connect(db)
    rq = tv.resolve_symbols(conn, "run_query")[0][0]
    radius = tv.impact_radius(conn, rq, depth=5)
    labels = {r["label"] for r in radius}
    conn.close()
    # handle reaches run_query transitively (handle->validate->run_query)
    assert any("handle" in x for x in labels)
    assert any("validate" in x for x in labels)


def test_impact_depth_bounds_frontier(tmp_path):
    db = _graph(tmp_path, _CHAIN)
    conn = sqlite3.connect(db)
    rq = tv.resolve_symbols(conn, "run_query")[0][0]
    shallow = tv.impact_radius(conn, rq, depth=1)
    labels = {r["label"] for r in shallow}
    conn.close()
    # depth 1 reaches direct callers (validate, other) but NOT handle (2 hops up)
    assert any("validate" in x for x in labels)
    assert not any("handle" in x for x in labels)


def test_shortest_path_directed(tmp_path):
    db = _graph(tmp_path, _CHAIN)
    conn = sqlite3.connect(db)
    s = tv.resolve_symbols(conn, "handle")[0][0]
    t = tv.resolve_symbols(conn, "run_query")[0][0]
    hops = tv.shortest_path(conn, s, t)
    conn.close()
    assert hops is not None and len(hops) == 2
    assert hops[0]["from"].endswith("handle") and hops[-1]["to"].endswith("run_query")
    # site is the call line, not the def line
    assert all(":" in h["site"] for h in hops)


def test_no_reverse_path_when_directed(tmp_path):
    db = _graph(tmp_path, _CHAIN)
    conn = sqlite3.connect(db)
    s = tv.resolve_symbols(conn, "handle")[0][0]
    t = tv.resolve_symbols(conn, "run_query")[0][0]
    # sink -> source is NOT a directed path
    assert tv.shortest_path(conn, t, s) is None
    conn.close()


def test_path_strength_is_weakest_hop():
    assert tv.path_strength([{"provenance": "EXTRACTED"}, {"provenance": "INFERRED"}]) == "INFERRED"
    assert tv.path_strength([{"provenance": "EXTRACTED"}, {"provenance": "EXTRACTED"}]) == "EXTRACTED"
    assert tv.path_strength([{"provenance": "AMBIGUOUS"}, {"provenance": "INFERRED"}]) == "AMBIGUOUS"
    assert tv.path_strength([]) == "EXTRACTED"


def test_cross_file_path_is_capped_inferred(tmp_path):
    db = _graph(tmp_path, {
        "a.py": "def handle():\n    run_query()\n",
        "b.py": "def run_query():\n    pass\n",
    })
    conn = sqlite3.connect(db)
    s = tv.resolve_symbols(conn, "handle")[0][0]
    t = tv.resolve_symbols(conn, "run_query")[0][0]
    hops = tv.shortest_path(conn, s, t)
    conn.close()
    assert tv.path_strength(hops) == "INFERRED"   # name-bridged across files


# --------------------------------------------------------- CLI recoverable states
def test_cli_symbol_not_found_is_recoverable(tmp_path, capsys):
    db = _graph(tmp_path, _CHAIN)
    rc = tv.main(["callers", "--db", db, "--symbol", "does_not_exist"])
    assert rc == 0
    assert "not found" in capsys.readouterr().out


def test_cli_no_path_is_recoverable(tmp_path, capsys):
    db = _graph(tmp_path, {"a.py": "def x():\n    pass\ndef y():\n    pass\n"})
    rc = tv.main(["path", "--db", db, "--from", "x", "--to", "y"])
    assert rc == 0
    assert "no directed call path" in capsys.readouterr().out


def test_cli_path_reports_strength(tmp_path, capsys):
    db = _graph(tmp_path, _CHAIN)
    rc = tv.main(["path", "--db", db, "--from", "handle", "--to", "run_query"])
    assert rc == 0
    assert "path strength" in capsys.readouterr().out


def test_cli_bad_db_errors(tmp_path):
    bad = tmp_path / "nope.sqlite"
    bad.write_text("not a db", encoding="utf-8")
    assert tv.main(["callers", "--db", str(bad), "--symbol", "x"]) == 2
