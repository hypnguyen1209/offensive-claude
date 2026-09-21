"""Tests for finding_store.py - scoped FTS5 store, 3-layer retrieval, redaction, token economics."""
import sys
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[3] / "engine"
sys.path.insert(0, str(ENGINE))

import pytest  # noqa: E402
import finding_store as fs  # noqa: E402


def _store(tmp_path, scope="acme"):
    return fs.open_store(str(tmp_path / "f.db"), scope=scope, create=True)


def _f(title, body="", *, cwe="CWE-79", severity="high", phase="exploit", status="confirmed", scope=None):
    d = {"title": title, "body": body, "cwe": cwe, "severity": severity, "phase": phase,
         "status": status}
    if scope is not None:
        d["scope"] = scope
    return d


# --------------------------------------------------------- write + retrieval
def test_add_and_get_roundtrip(tmp_path):
    conn = _store(tmp_path)
    fid = fs.add_finding(conn, _f("SSRF in webhook", "reached 169.254.169.254 metadata"), ts=1000.0)
    rows = fs.get(conn, [fid])
    conn.close()
    assert len(rows) == 1 and rows[0]["title"] == "SSRF in webhook"
    assert "metadata" in rows[0]["body"]


def test_search_compact_index_matches(tmp_path):
    conn = _store(tmp_path)
    fs.add_finding(conn, _f("SSRF in webhook", "server side request forgery to metadata"), ts=1.0)
    fs.add_finding(conn, _f("Reflected XSS", "script executes in victim browser"), ts=2.0)
    hits = fs.search(conn, "metadata forgery")
    conn.close()
    assert any("SSRF" in h["title"] for h in hits)
    # layer-1 rows are COMPACT: no body field
    assert all("body" not in h for h in hits)


def test_search_ranks_severity(tmp_path):
    conn = _store(tmp_path)
    fs.add_finding(conn, _f("low sqli note", "sql injection", severity="low"), ts=1.0)
    fs.add_finding(conn, _f("critical sqli", "sql injection", severity="critical"), ts=2.0)
    hits = fs.search(conn, "sql injection")
    conn.close()
    assert hits[0]["severity"] == "critical"


def test_get_preserves_requested_order_and_skips_unknown(tmp_path):
    conn = _store(tmp_path)
    a = fs.add_finding(conn, _f("A", "a"), ts=1.0)
    b = fs.add_finding(conn, _f("B", "b"), ts=2.0)
    rows = fs.get(conn, [b, "nonexistent", a])
    conn.close()
    assert [r["fid"] for r in rows] == [b, a]


def test_timeline_neighbours_anchor(tmp_path):
    conn = _store(tmp_path)
    fids = [fs.add_finding(conn, _f(f"F{i}", f"body{i}"), ts=float(i)) for i in range(5)]
    tl = fs.timeline(conn, fids[2], window=1)
    conn.close()
    fids_out = [r["fid"] for r in tl]
    assert fids[2] in fids_out
    assert any(r["is_anchor"] for r in tl)
    # window=1 -> anchor + one before + one after
    assert fids[1] in fids_out and fids[3] in fids_out
    assert fids[0] not in fids_out


def test_timeline_unknown_anchor_empty(tmp_path):
    conn = _store(tmp_path)
    fs.add_finding(conn, _f("x"), ts=1.0)
    assert fs.timeline(conn, "deadbeef") == []
    conn.close()


def test_reAdd_updates_in_place(tmp_path):
    conn = _store(tmp_path)
    fid1 = fs.add_finding(conn, _f("dup title", "first", cwe="CWE-89"), ts=1.0)
    fid2 = fs.add_finding(conn, _f("dup title", "second", cwe="CWE-89"), ts=2.0)
    assert fid1 == fid2                                  # same (scope,title,cwe) -> same fid
    rows = fs.get(conn, [fid1])
    tel = fs.telemetry(conn)
    conn.close()
    assert rows[0]["body"] == "second"                  # updated, not duplicated
    assert tel["findings"] == 1


# --------------------------------------------------------- scope isolation
def test_scope_mismatch_rejected(tmp_path):
    conn = _store(tmp_path, scope="acme")
    with pytest.raises(fs.ScopeError):
        fs.add_finding(conn, _f("evil", scope="other-corp"), ts=1.0)
    conn.close()


def test_unspecified_scope_defaults_to_bound(tmp_path):
    conn = _store(tmp_path, scope="acme")
    fid = fs.add_finding(conn, _f("no scope given"), ts=1.0)   # no scope in the finding dict
    rows = fs.get(conn, [fid])
    conn.close()
    assert rows[0]["scope"] == "acme"


def test_refuse_rebind_scope(tmp_path):
    db = str(tmp_path / "f.db")
    fs.open_store(db, scope="acme").close()
    with pytest.raises(fs.ScopeError):
        fs.open_store(db, scope="different")


# --------------------------------------------------------- write-boundary redaction
def test_private_span_stripped_before_store(tmp_path):
    conn = _store(tmp_path)
    fid = fs.add_finding(conn, _f("t", "public <private>client=MegaBank</private> tail"), ts=1.0)
    rows = fs.get(conn, [fid])
    conn.close()
    assert "MegaBank" not in rows[0]["body"]
    assert "[private omitted]" in rows[0]["body"]


def test_secret_redacted_before_store(tmp_path):
    conn = _store(tmp_path)
    fid = fs.add_finding(conn, _f("t", "key AKIAIOSFODNN7EXAMPLE here"), ts=1.0)
    rows = fs.get(conn, [fid])
    conn.close()
    assert "AKIAIOSFODNN7EXAMPLE" not in rows[0]["body"]
    assert "REDACTED secret" in rows[0]["body"]


def test_invalid_severity_rejected(tmp_path):
    conn = _store(tmp_path)
    with pytest.raises(fs.StoreError):
        fs.add_finding(conn, _f("t", severity="spicy"), ts=1.0)
    conn.close()


# --------------------------------------------------------- token economics
def test_recall_cost_and_plan_budget(tmp_path):
    conn = _store(tmp_path)
    big = fs.add_finding(conn, _f("crit big", "X" * 4000, severity="critical"), ts=1.0)
    small = fs.add_finding(conn, _f("low small", "y" * 40, severity="low"), ts=2.0)
    cost = fs.recall_cost(conn, [big, small])
    plan = fs.plan_recall(conn, [big, small], budget=50)   # only the small one fits
    conn.close()
    assert cost > 1000
    # critical is tried first but is too big; no silent truncation -> it's in dropped
    assert big in plan["dropped"]
    assert small in plan["included"]


def test_telemetry_is_content_free(tmp_path):
    conn = _store(tmp_path)
    fs.add_finding(conn, _f("secret-ish title", "AKIAIOSFODNN7EXAMPLE", severity="high"), ts=1.0)
    tel = fs.telemetry(conn)
    conn.close()
    blob = str(tel)
    assert "AKIAIOSFODNN7EXAMPLE" not in blob and "secret-ish title" not in blob
    assert tel["findings"] == 1 and tel["by_severity"]["high"] == 1
    assert tel["rediscovery_estimate"] > tel["stored_body_tokens"]


# --------------------------------------------------------- integrity
def test_count_mismatch_auto_rebuild(tmp_path):
    if not fs._HAS_FTS5:
        pytest.skip("no FTS5 in this build")
    db = str(tmp_path / "f.db")
    conn = fs.open_store(db, scope="acme")
    fs.add_finding(conn, _f("a", "alpha content"), ts=1.0)
    fs.add_finding(conn, _f("b", "beta content"), ts=2.0)
    # corrupt the mirror: wipe the FTS index behind the triggers' back
    conn.execute("DELETE FROM findings_fts")
    conn.commit()
    assert conn.execute("SELECT COUNT(*) FROM findings_fts").fetchone()[0] == 0
    res = fs.verify_integrity(conn, rebuild=True)
    conn.close()
    assert res["rebuilt"] is True and res["fts"] == 2


def test_open_reruns_integrity(tmp_path):
    db = str(tmp_path / "f.db")
    conn = fs.open_store(db, scope="acme")
    fs.add_finding(conn, _f("a", "alpha"), ts=1.0)
    conn.close()
    conn2 = fs.open_store(db)                            # reopen -> integrity check runs, no crash
    hits = fs.search(conn2, "alpha")
    conn2.close()
    assert any(h["title"] == "a" for h in hits)


# --------------------------------------------------------- CLI
def test_cli_init_add_search(tmp_path, capsys):
    db = str(tmp_path / "f.db")
    assert fs.main(["--db", db, "init", "--scope", "acme"]) == 0
    capsys.readouterr()
    import json
    finding = json.dumps({"title": "SSRF metadata", "body": "reached imds", "cwe": "CWE-918",
                          "severity": "high", "phase": "exploit"})
    assert fs.main(["--db", db, "add", "--json", finding]) == 0
    capsys.readouterr()
    assert fs.main(["--db", db, "search", "--query", "imds metadata"]) == 0
    out = capsys.readouterr().out
    assert "SSRF metadata" in out


def test_cli_scope_violation_exit_3(tmp_path, capsys):
    db = str(tmp_path / "f.db")
    fs.main(["--db", db, "init", "--scope", "acme"])
    capsys.readouterr()
    import json
    bad = json.dumps({"title": "x", "scope": "other", "severity": "low"})
    rc = fs.main(["--db", db, "add", "--json", bad])
    assert rc == 3


def test_cli_get_missing_db_errors(tmp_path):
    assert fs.main(["--db", str(tmp_path / "nope.db"), "get", "--ids", "a"]) == 2


# --------------------------------------------------------- contextual-BM25 (cookbook adoption)
def test_context_is_folded_into_body_and_searchable(tmp_path):
    conn = _store(tmp_path)
    # body has NO 'kubelet' token; only the situating context does. Contextual-BM25 must let a search
    # for 'kubelet' still find this finding.
    fs.add_finding(conn, _f("SSRF in metadata proxy", "reached the internal endpoint",
                            cwe="CWE-918"), ts=1.0)  # control: unrelated finding
    fid = fs.add_finding(conn, {"title": "SSRF egress", "body": "fetch() hits an internal IP",
                                "cwe": "CWE-918", "severity": "high", "phase": "exploit",
                                "status": "confirmed",
                                "context": "reachable from the unauth kubelet read-only port 10255"},
                         ts=2.0)
    hits = fs.search(conn, "kubelet")
    rows = fs.get(conn, [fid])
    conn.close()
    assert any(h["fid"] == fid for h in hits)          # found via the context token
    assert "Context:" in rows[0]["body"] and "kubelet" in rows[0]["body"]


def test_context_absent_is_unchanged(tmp_path):
    conn = _store(tmp_path)
    fid = fs.add_finding(conn, _f("plain finding", "just a body"), ts=1.0)
    rows = fs.get(conn, [fid])
    conn.close()
    assert rows[0]["body"] == "just a body"             # no Context: prefix when none supplied
