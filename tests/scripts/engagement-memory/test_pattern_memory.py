"""Tests for the cross-engagement pattern memory (schemas + pattern_db + rotation)."""
import json
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[3] / "skills" / "engagement-memory" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import pytest  # noqa: E402
import schemas  # noqa: E402
import pattern_db as pdb  # noqa: E402
import rotation  # noqa: E402


def pat(target="acme.com", vc="ssrf", technique="metadata", severity="high", cvss=9.1, ts=1000.0, **kw):
    return schemas.make_pattern(target, vc, technique=technique, severity=severity, cvss=cvss, ts=ts, **kw)


# --------------------------------------------------------- schemas
def test_make_and_validate_pattern():
    r = pat(cwe="cwe-918", attack_id="t1190", tech_stack=["NGINX", "aws", "aws"])
    assert r["cwe"] == "CWE-918" and r["attack_id"] == "T1190"
    assert r["tech_stack"] == ["aws", "nginx"]          # normalized, deduped, sorted
    schemas.validate_pattern(r)


@pytest.mark.parametrize("bad", [
    {"type": "pattern", "schema_version": 1, "vuln_class": "x", "severity": "high"},   # no target
    {"type": "pattern", "schema_version": 1, "target": "a", "severity": "high"},       # no vuln_class
    {"type": "pattern", "schema_version": 1, "target": "a", "vuln_class": "x", "severity": "huge"},
    {"type": "pattern", "schema_version": 99, "target": "a", "vuln_class": "x", "severity": "high"},
])
def test_validate_rejects(bad):
    with pytest.raises(schemas.SchemaError):
        schemas.validate_pattern(bad)


def test_cvss_range():
    with pytest.raises(schemas.SchemaError):
        schemas.make_pattern("a", "x", cvss=11.0)


def test_pattern_key_and_rank():
    a = pat(cvss=9.1, severity="critical", ts=1)
    b = pat(cvss=4.0, severity="medium", ts=2)
    assert schemas.rank_score(a) > schemas.rank_score(b)         # impact beats recency
    assert schemas.pattern_key(pat(target="ACME.com.")) == schemas.pattern_key(pat(target="acme.com"))


def test_merge_keeps_higher_impact_and_sums_count():
    a = pat(cvss=9.1, ts=10, tech_stack=["nginx"])
    b = pat(cvss=4.0, ts=20, tech_stack=["aws"])
    m = schemas.merge(a, b)
    assert m["cvss"] == 9.1 and m["count"] == 2 and m["ts"] == 20
    assert m["tech_stack"] == ["aws", "nginx"]


# --------------------------------------------------------- pattern_db
def test_record_load_merge(tmp_path):
    db = str(tmp_path / "p.jsonl")
    pdb.record(pat(cvss=9.1, ts=1), db)
    pdb.record(pat(cvss=9.1, ts=5), db)             # same key -> merge on read
    pdb.record(pat(vc="xss", technique="dom", cvss=6.1, ts=2), db)
    assert len(pdb.load(db)) == 3                   # journal keeps all
    m = pdb.merged(db)
    assert len(m) == 2                              # merged by key
    ssrf = [r for r in m if r["vuln_class"] == "ssrf"][0]
    assert ssrf["count"] == 2


def test_match_ranks_and_filters(tmp_path):
    db = str(tmp_path / "p.jsonl")
    pdb.record(pat(vc="ssrf", cvss=9.1, severity="critical", tech_stack=["aws"]), db)
    pdb.record(pat(vc="ssrf", technique="redis", cvss=5.0, severity="medium", tech_stack=["redis"]), db)
    pdb.record(pat(vc="xss", technique="stored", cvss=6.0, tech_stack=["react"]), db)
    recs = pdb.merged(db)
    ssrf = pdb.match(recs, vuln_class="ssrf")
    assert [r["technique"] for r in ssrf][0] == "metadata"     # highest cvss first
    assert pdb.match(recs, vuln_class="ssrf", tech_stack=["aws"])[0]["technique"] == "metadata"
    assert pdb.match(recs, vuln_class="ssrf", tech_stack=["redis"])[0]["technique"] == "redis"
    assert pdb.match(recs, vuln_class="xss", top=10)[0]["vuln_class"] == "xss"
    assert pdb.match(recs, top=1) and len(pdb.match(recs, top=1)) == 1


# --------------------------------------------------------- rotation
def test_compact_dedups_preserving_patterns(tmp_path):
    db = str(tmp_path / "p.jsonl")
    for ts in range(5):
        pdb.record(pat(cvss=9.1, ts=ts), db)             # 5 dupes of one key
    pdb.record(pat(vc="xss", technique="dom", cvss=6.0, ts=1), db)
    before, after = rotation.compact(db)
    assert before == 6 and after == 2                    # 5 merged to 1, distinct kept
    assert len(pdb.load(db)) == 2                         # file rewritten
    ssrf = [r for r in pdb.load(db) if r["vuln_class"] == "ssrf"][0]
    assert ssrf["count"] == 5                             # knowledge preserved (count), not discarded


def test_rotate_audit(tmp_path):
    audit = str(tmp_path / "audit.log")
    Path(audit).write_text("x" * 100, encoding="utf-8")
    assert rotation.rotate_audit(audit, max_bytes=10, keep=2) is True
    assert Path(audit + ".1").exists() and Path(audit).read_text() == ""
    assert rotation.rotate_audit(audit, max_bytes=10_000) is False     # under cap


# --------------------------------------------------------- CLI
def test_cli_record_match_compact_stats(tmp_path, capsys):
    db = str(tmp_path / "p.jsonl")
    assert pdb.main(["--db", db, "record", "--target", "acme.com", "--vuln-class", "ssrf",
                     "--cwe", "CWE-918", "--severity", "high", "--cvss", "9.1",
                     "--attack-id", "T1190", "--tech-stack", "nginx,aws"]) == 0
    assert pdb.main(["--db", db, "match", "--vuln-class", "ssrf", "--json"]) == 0
    assert "T1190" in capsys.readouterr().out
    assert pdb.main(["--db", db, "compact"]) == 0
    assert pdb.main(["--db", db, "stats"]) == 0


def test_cli_record_json(tmp_path, capsys):
    db = str(tmp_path / "p.jsonl")
    finding = json.dumps({"target": "acme.com", "vuln_class": "rce", "cwe": "CWE-78",
                          "severity": "critical", "cvss": 9.8, "attck_id": "T1059",
                          "evidence": ["logs/x.txt"]})
    assert pdb.main(["--db", db, "record", "--json", finding]) == 0
    recs = pdb.merged(db)
    assert recs[0]["attack_id"] == "T1059" and recs[0]["evidence_ref"] == "logs/x.txt"
