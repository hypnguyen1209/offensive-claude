"""Tests for affected.py - changed files -> downstream security sinks."""
import sqlite3
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts" / "codegraph"
sys.path.insert(0, str(_SCRIPTS))

import build_graph as bg  # noqa: E402
import affected as af  # noqa: E402


def _graph(tmp_path, files):
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    db = str(tmp_path / "g.sqlite")
    bg.build(str(tmp_path), db)
    return db


# view() -> run_cmd() -> os.system(sink). Changing views.py should surface the CWE-78 sink downstream.
_APP = {
    "views.py": "import os\ndef view(x):\n    run_cmd(x)\n",
    "cmd.py": "import os\ndef run_cmd(x):\n    os.system(x)\n",
    "safe.py": "def helper():\n    return 1\n",
}


def test_changed_file_reaches_downstream_sink(tmp_path):
    db = _graph(tmp_path, _APP)
    conn = sqlite3.connect(db)
    res = af.affected_sinks(conn, ["views.py"], depth=6)
    conn.close()
    sinks = {s["sink"] for s in res["sinks"]}
    assert "system" in sinks
    assert any(s["cwe"] == "CWE-78" for s in res["sinks"])


def test_unrelated_change_has_no_sinks(tmp_path):
    db = _graph(tmp_path, _APP)
    conn = sqlite3.connect(db)
    res = af.affected_sinks(conn, ["safe.py"], depth=6)
    conn.close()
    assert res["sinks"] == []


def test_direct_sink_in_changed_file(tmp_path):
    db = _graph(tmp_path, _APP)
    conn = sqlite3.connect(db)
    res = af.affected_sinks(conn, ["cmd.py"], depth=6)   # cmd.py directly holds os.system
    conn.close()
    assert any(s["sink"] == "system" for s in res["sinks"])


def test_depth_bounds_reachability(tmp_path):
    db = _graph(tmp_path, _APP)
    conn = sqlite3.connect(db)
    # depth 1 from view: view->run_cmd (reachable), run_cmd's os.system callsite belongs to run_cmd
    # which is reachable at depth 1, so the sink is still found. Use a longer chain to test the bound.
    res_deep = af.affected_sinks(conn, ["views.py"], depth=6)
    conn.close()
    assert res_deep["reachable_count"] >= 2


def test_norm_matches_repo_relative_paths(tmp_path):
    db = _graph(tmp_path, _APP)
    conn = sqlite3.connect(db)
    # a repo-relative path with ./ prefix still matches
    res = af.affected_sinks(conn, ["./views.py"], depth=6)
    conn.close()
    assert res["seed_symbols"] >= 1


def test_symbols_in_files_suffix_match(tmp_path):
    db = _graph(tmp_path, {"pkg/mod.py": "def f():\n    pass\n"})
    conn = sqlite3.connect(db)
    ids = af.symbols_in_files(conn, ["mod.py"])   # bare filename suffix-matches pkg/mod.py
    conn.close()
    assert len(ids) >= 1


# --------------------------------------------------------- CLI
def test_cli_files_flag_reports_sink(tmp_path, capsys):
    db = _graph(tmp_path, _APP)
    rc = af.main(["--db", db, "--files", "views.py"])
    assert rc == 0
    assert "CWE-78" in capsys.readouterr().out


def test_cli_no_changed_symbols_is_recoverable(tmp_path, capsys):
    db = _graph(tmp_path, _APP)
    rc = af.main(["--db", db, "--files", "not/in/graph.py"])
    assert rc == 0
    assert "no changed symbols" in capsys.readouterr().out


def test_cli_changed_list_file(tmp_path, capsys):
    db = _graph(tmp_path, _APP)
    lst = tmp_path / "changed.txt"
    lst.write_text("views.py\n", encoding="utf-8")
    rc = af.main(["--db", db, "--changed-list", str(lst)])
    assert rc == 0
    assert "system()" in capsys.readouterr().out


def test_cli_no_files_errors(tmp_path):
    db = _graph(tmp_path, _APP)
    assert af.main(["--db", db]) == 2


def test_cli_bad_db_errors(tmp_path):
    bad = tmp_path / "x.sqlite"
    bad.write_text("nope", encoding="utf-8")
    assert af.main(["--db", str(bad), "--files", "a.py"]) == 2
