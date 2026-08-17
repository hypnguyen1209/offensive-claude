"""Tests for build_graph.py - the sqlite source-to-sink code graph."""
import sqlite3
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts" / "codegraph"
sys.path.insert(0, str(_SCRIPTS))

import build_graph as bg  # noqa: E402


def _write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def _rows(db, sql, args=()):
    conn = sqlite3.connect(db)
    try:
        return conn.execute(sql, args).fetchall()
    finally:
        conn.close()


# --------------------------------------------------------- node id stability
def test_node_id_is_line_independent_and_stable():
    a = bg.node_id("function", "app.py", "authenticate")
    b = bg.node_id("function", "app.py", "authenticate")
    assert a == b and len(a) == 16
    assert bg.node_id("function", "app.py", "other") != a


# --------------------------------------------------------- extraction
def test_extract_functions_classes_methods():
    src = (
        "def top():\n"
        "    helper()\n"
        "class C:\n"
        "    def m(self):\n"
        "        top()\n"
    )
    ex = bg.extract_python("app.py", src, 0)
    kinds = {s.qualified_name: s.kind for s in ex.symbols}
    assert kinds["top"] == "function"
    assert kinds["C"] == "class"
    assert kinds["C.m"] == "method"          # immediate class scope -> method
    assert kinds["<module>"] == "module"
    callee_names = {c.callee_name for c in ex.callsites}
    assert {"helper", "top"} <= callee_names


def test_extract_syntax_error_is_empty_not_fatal():
    ex = bg.extract_python("bad.py", "def (:\n", 0)
    assert ex.symbols == [] and ex.callsites == []


# --------------------------------------------------------- provenance resolution
def test_same_file_call_is_extracted(tmp_path):
    _write(tmp_path, "app.py", "def a():\n    b()\ndef b():\n    pass\n")
    db = str(tmp_path / "g.sqlite")
    res = bg.build(str(tmp_path), db)
    # a -> b is a bare same-file call -> EXTRACTED
    provs = [r[0] for r in _rows(db, "SELECT provenance FROM edges WHERE kind='calls'")]
    assert bg.EXTRACTED in provs
    assert res.provenance[bg.EXTRACTED] >= 1


def test_cross_file_name_bridge_is_inferred(tmp_path):
    _write(tmp_path, "a.py", "def caller():\n    helper()\n")
    _write(tmp_path, "b.py", "def helper():\n    pass\n")
    db = str(tmp_path / "g.sqlite")
    bg.build(str(tmp_path), db)
    provs = [r[0] for r in _rows(db, "SELECT provenance FROM edges WHERE kind='calls'")]
    assert bg.INFERRED in provs             # resolved by name across files, not by import


def test_ambiguous_when_name_matches_multiple(tmp_path):
    _write(tmp_path, "a.py", "def caller():\n    handle()\n")
    _write(tmp_path, "b.py", "def handle():\n    pass\n")
    _write(tmp_path, "c.py", "def handle():\n    pass\n")
    db = str(tmp_path / "g.sqlite")
    bg.build(str(tmp_path), db)
    provs = [r[0] for r in _rows(db, "SELECT provenance FROM edges WHERE kind='calls'")]
    assert provs.count(bg.AMBIGUOUS) >= 2    # an edge to each candidate, all AMBIGUOUS


def test_unresolved_call_goes_to_unresolved_refs_not_edges(tmp_path):
    _write(tmp_path, "a.py", "def caller():\n    nonexistent_sink()\n")
    db = str(tmp_path / "g.sqlite")
    bg.build(str(tmp_path), db)
    refs = _rows(db, "SELECT ref_name FROM unresolved_refs")
    assert ("nonexistent_sink",) in refs
    edge_targets = _rows(db, "SELECT target FROM edges WHERE kind='calls'")
    assert edge_targets == []               # no edge to a phantom target


def test_contains_edges_link_module_class_method(tmp_path):
    _write(tmp_path, "app.py", "class C:\n    def m(self):\n        pass\n")
    db = str(tmp_path / "g.sqlite")
    bg.build(str(tmp_path), db)
    contains = _rows(db, "SELECT COUNT(*) FROM edges WHERE kind='contains'")[0][0]
    assert contains >= 2                    # module->C and C->m


# --------------------------------------------------------- incremental + shrink-guard
def test_incremental_skips_unchanged_files(tmp_path):
    _write(tmp_path, "a.py", "def a():\n    pass\n")
    db = str(tmp_path / "g.sqlite")
    bg.build(str(tmp_path), db)
    res2 = bg.build(str(tmp_path), db, incremental=True)
    assert res2.files_skipped_unchanged == 1 and res2.files_indexed == 0


def test_incremental_reindexes_changed_and_drops_deleted(tmp_path):
    _write(tmp_path, "a.py", "def a():\n    pass\n")
    b = _write(tmp_path, "b.py", "def b():\n    pass\n")
    db = str(tmp_path / "g.sqlite")
    bg.build(str(tmp_path), db)
    b.unlink()
    _write(tmp_path, "a.py", "def a():\n    pass\ndef a2():\n    pass\n")
    res = bg.build(str(tmp_path), db, incremental=True)
    names = {r[0] for r in _rows(db, "SELECT name FROM symbols")}
    assert "a2" in names and "b" not in names
    assert res.files_indexed == 1

def test_shrink_guard_refuses_smaller_graph(tmp_path):
    _write(tmp_path, "a.py", "def a():\n    pass\ndef b():\n    pass\ndef c():\n    pass\n")
    db = str(tmp_path / "g.sqlite")
    first = bg.build(str(tmp_path), db)
    assert first.symbols >= 4
    # now shrink the tree drastically and rebuild (non-incremental)
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    res = bg.build(str(tmp_path), db)
    assert res.shrunk_refused is True
    # and with --allow-shrink it goes through
    res2 = bg.build(str(tmp_path), db, allow_shrink=True)
    assert res2.shrunk_refused is False


def test_generated_files_flagged(tmp_path):
    _write(tmp_path, "api_pb2.py", "def gen():\n    pass\n")
    _write(tmp_path, "hand.py", "def real():\n    pass\n")
    db = str(tmp_path / "g.sqlite")
    bg.build(str(tmp_path), db)
    gen = dict(_rows(db, "SELECT name, generated FROM symbols WHERE name IN ('gen','real')"))
    assert gen["gen"] == 1 and gen["real"] == 0


# --------------------------------------------------------- CLI
def test_cli_build_and_stats(tmp_path, capsys):
    _write(tmp_path, "a.py", "def a():\n    b()\ndef b():\n    pass\n")
    db = str(tmp_path / "g.sqlite")
    assert bg.main([str(tmp_path), "--db", db]) == 0
    capsys.readouterr()
    assert bg.main([str(tmp_path), "--db", db, "--stats"]) == 0
    assert "symbols=" in capsys.readouterr().out


def test_cli_empty_tree_is_recoverable_not_error(tmp_path, capsys):
    db = str(tmp_path / "g.sqlite")
    rc = bg.main([str(tmp_path), "--db", db])
    assert rc == 0
    assert "indexed 0 symbols" in capsys.readouterr().out


def test_cli_shrink_refusal_exit_3(tmp_path):
    _write(tmp_path, "a.py", "def a():\n    pass\ndef b():\n    pass\n")
    db = str(tmp_path / "g.sqlite")
    bg.main([str(tmp_path), "--db", db])
    (tmp_path / "a.py").write_text("x=1\n", encoding="utf-8")
    assert bg.main([str(tmp_path), "--db", db]) == 3
