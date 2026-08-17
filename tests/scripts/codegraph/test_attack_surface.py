"""Tests for attack_surface.py - trust zones, god-nodes, boundary crossings, worklist."""
import sqlite3
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts" / "codegraph"
sys.path.insert(0, str(_SCRIPTS))

import build_graph as bg  # noqa: E402
import attack_surface as asf  # noqa: E402


def _graph(tmp_path, files):
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    db = str(tmp_path / "g.sqlite")
    bg.build(str(tmp_path), db)
    return db


# two packages: web/ calls into core/, and core/ holds a command sink.
_APP = {
    "web/handler.py": "import core.db as db\ndef handle(x):\n    run_query(x)\n",
    "core/db.py": "import os\ndef run_query(x):\n    os.system(x)\ndef helper():\n    run_query('a')\n",
}


def test_zone_of_first_segment():
    assert asf._zone_of("web/handler.py") == "web"
    assert asf._zone_of("core/db.py") == "core"
    assert asf._zone_of("top.py") == "<root>"
    assert asf._zone_of("./web/x.py") == "web"


def test_trust_zones_group_by_package(tmp_path):
    db = _graph(tmp_path, _APP)
    conn = sqlite3.connect(db)
    zones = asf.trust_zones(conn)
    conn.close()
    assert "web" in zones and "core" in zones


def test_connected_components_returns_sizes(tmp_path):
    db = _graph(tmp_path, _APP)
    conn = sqlite3.connect(db)
    sizes = asf.connected_components(conn)
    conn.close()
    # run_query is called from handle + helper, so those are one connected island
    assert isinstance(sizes, list) and sizes and sizes[0] >= 2


def test_god_nodes_rank_by_degree(tmp_path):
    db = _graph(tmp_path, _APP)
    conn = sqlite3.connect(db)
    gods = asf.god_nodes(conn, top_n=5)
    conn.close()
    # run_query has the highest fan-in (called by handle + helper)
    assert gods and any("run_query" in g["label"] for g in gods)
    assert gods[0]["degree"] >= 2


def test_god_nodes_demote_generated(tmp_path):
    db = _graph(tmp_path, {
        "hand.py": "def a():\n    shared()\ndef shared():\n    pass\n",
        "gen.py": "# @generated\ndef g():\n    shared2()\ndef shared2():\n    g()\n    g()\n",
    })
    conn = sqlite3.connect(db)
    gods = asf.god_nodes(conn, top_n=10)
    conn.close()
    # hand-written symbols must sort before generated ones regardless of raw degree
    first_gen = next((i for i, g in enumerate(gods) if g["generated"]), len(gods))
    last_hand = max((i for i, g in enumerate(gods) if not g["generated"]), default=-1)
    assert last_hand < first_gen


def test_surprising_connections_cross_zone(tmp_path):
    db = _graph(tmp_path, _APP)
    conn = sqlite3.connect(db)
    crossings = asf.surprising_connections(conn)
    conn.close()
    # web/handle -> core/run_query crosses the web->core trust boundary
    assert any(c["from_zone"] == "web" and c["to_zone"] == "core" for c in crossings)


def test_same_zone_calls_not_surprising(tmp_path):
    db = _graph(tmp_path, {
        "core/a.py": "def x():\n    y()\ndef y():\n    pass\n",
    })
    conn = sqlite3.connect(db)
    crossings = asf.surprising_connections(conn)
    conn.close()
    assert crossings == []


def test_worklist_flags_crossing_into_sink(tmp_path):
    db = _graph(tmp_path, _APP)
    conn = sqlite3.connect(db)
    wl = asf.worklist(conn, top_n=10)
    conn.close()
    # the web->core crossing lands on run_query, which invokes os.system (CWE-78)
    assert wl
    assert any("CWE-78" in "; ".join(w["why"]) for w in wl)


def test_empty_graph_worklist_empty(tmp_path):
    db = _graph(tmp_path, {"a.py": "x = 1\n"})
    conn = sqlite3.connect(db)
    assert asf.worklist(conn) == []
    conn.close()


# --------------------------------------------------------- CLI
def test_cli_reports_zones_and_crossings(tmp_path, capsys):
    db = _graph(tmp_path, _APP)
    rc = asf.main(["--db", db])
    assert rc == 0
    out = capsys.readouterr().out
    assert "trust zones" in out
    assert "god-nodes" in out


def test_cli_json(tmp_path, capsys):
    db = _graph(tmp_path, _APP)
    rc = asf.main(["--db", db, "--json"])
    assert rc == 0
    import json
    m = json.loads(capsys.readouterr().out)
    assert "god_nodes" in m and "worklist" in m and "trust_zones" in m


def test_cli_empty_graph_recoverable(tmp_path, capsys):
    db = str(tmp_path / "g.sqlite")
    bg.build(str(tmp_path), db)   # no source files -> empty graph
    rc = asf.main(["--db", db])
    assert rc == 0
    assert "empty graph" in capsys.readouterr().out


def test_cli_bad_db_errors(tmp_path):
    bad = tmp_path / "x.sqlite"
    bad.write_text("nope", encoding="utf-8")
    assert asf.main(["--db", str(bad)]) == 2
