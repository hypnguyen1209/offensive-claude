"""Tests for working_context.py - the WORKING-CONTEXT.md renderer."""
import sys
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[3] / "engine"
sys.path.insert(0, str(ENGINE))

import working_context as wc  # noqa: E402
import finding_store as fs  # noqa: E402


def test_render_has_core_sections():
    md = wc.render(scope="acme", phase="exploit", constraints=["no DoS"],
                   queues={"leads": ["SSRF webhook"]})
    assert "# WORKING CONTEXT" in md
    assert "## Current truth" in md and "acme" in md and "exploit" in md
    assert "## Constraints (ROE)" in md and "no DoS" in md
    assert "## Active queues" in md and "SSRF webhook" in md


def test_render_empty_states_are_explicit():
    md = wc.render()
    assert "(unbound)" in md
    assert "none recorded" in md          # constraints
    assert "no active queues" in md
    assert "no findings recorded yet" in md


def test_finding_index_sorted_by_severity():
    findings = [
        {"severity": "low", "cwe": "CWE-200", "status": "possible", "title": "info leak", "fid": "a"},
        {"severity": "critical", "cwe": "CWE-89", "status": "confirmed", "title": "sqli", "fid": "b"},
    ]
    md = wc.render(findings=findings)
    assert md.index("sqli") < md.index("info leak")     # critical listed before low
    assert "| critical |" in md


def test_finding_title_with_pipe_stays_one_table_row():
    findings = [{"severity": "high", "cwe": "CWE-89", "status": "confirmed",
                 "title": "sqli in a|b\nsecond line", "fid": "x"}]
    md = wc.render(findings=findings)
    # the pipe is escaped and the newline flattened, so the row is not broken into two
    assert "a\\|b" in md
    rows = [ln for ln in md.splitlines() if ln.startswith("| ") and "sqli" in ln]
    assert len(rows) == 1


def test_private_span_stripped_from_constraints():
    md = wc.render(constraints=["visible <private>client=MegaBank</private> constraint"])
    assert "MegaBank" not in md
    assert "[private omitted]" in md


def test_secret_masked_in_queue_item():
    md = wc.render(queues={"leads": ["token AKIAIOSFODNN7EXAMPLE found"]})
    assert "AKIAIOSFODNN7EXAMPLE" not in md
    assert "REDACTED secret" in md


def test_telemetry_section_rendered():
    md = wc.render(telemetry={"findings": 3, "by_severity": {"high": 2, "low": 1},
                              "stored_body_tokens": 100, "rediscovery_estimate": 800})
    assert "## Recall economics" in md
    assert "Findings stored: 3" in md
    assert "~800" in md


def test_output_is_deterministic_without_updated():
    a = wc.render(scope="acme", phase="recon")
    b = wc.render(scope="acme", phase="recon")
    assert a == b
    assert "Updated:" not in a               # no timestamp unless explicitly passed


def test_updated_line_when_passed():
    md = wc.render(scope="acme", updated="2026-08-17T10:00Z")
    assert "Updated: 2026-08-17T10:00Z" in md


# --------------------------------------------------------- from_store integration
def test_from_store_pulls_compact_index(tmp_path):
    conn = fs.open_store(str(tmp_path / "f.db"), scope="acme")
    fs.add_finding(conn, {"title": "SSRF metadata", "body": "reached imds", "cwe": "CWE-918",
                          "severity": "high", "phase": "exploit", "status": "confirmed"}, ts=1.0)
    md = wc.from_store(conn, phase="exploit")
    conn.close()
    assert "SSRF metadata" in md
    assert "acme" in md                       # scope defaulted from the bound store
    assert "reached imds" not in md           # bodies never enter the compact context file
    assert "## Recall economics" in md


# --------------------------------------------------------- CLI
def test_cli_writes_file(tmp_path, capsys):
    out = tmp_path / "WORKING-CONTEXT.md"
    rc = wc.main(["--scope", "acme", "--phase", "recon", "--constraint", "no DoS",
                  "--queue", "leads=a,b", "--out", str(out)])
    assert rc == 0
    text = out.read_text(encoding="utf-8")
    assert "acme" in text and "no DoS" in text and "leads (2)" in text


def test_cli_from_store(tmp_path, capsys):
    db = str(tmp_path / "f.db")
    fs.open_store(db, scope="acme").close()
    rc = wc.main(["--db", db, "--phase", "exploit", "--stdout"])
    assert rc == 0
    assert "# WORKING CONTEXT" in capsys.readouterr().out


def test_cli_missing_db_errors(tmp_path):
    assert wc.main(["--db", str(tmp_path / "nope.db"), "--stdout"]) == 2
