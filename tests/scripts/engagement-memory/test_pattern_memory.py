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


def _fixture(*parts):
    """Build a secret-SHAPED test value from parts, so no contiguous real-secret literal exists in
    source (defeats GitHub push-protection / secret scanners). The joined value is fake regardless."""
    return "".join(parts)


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
    assert Path(audit + ".1").exists()
    assert json.loads(Path(audit).read_text().splitlines()[0])["type"] == "retention_gap"  # gap marker written
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


# ========================================================= PR1: audit + auto-gc + profiles
def test_make_validate_audit():
    a = schemas.make_audit("write", "record", target="ACME.com", outcome="success", dry_run=True)
    assert a["type"] == "audit" and a["target"] == "acme.com" and a["dry_run"] is True
    schemas.validate_audit(a)


@pytest.mark.parametrize("bad", [
    {"type": "audit", "schema_version": 1, "action_class": "hack", "outcome": "success", "dry_run": False},
    {"type": "audit", "schema_version": 1, "action_class": "read", "outcome": "maybe", "dry_run": False},
    {"type": "audit", "schema_version": 1, "action_class": "read", "outcome": "success", "dry_run": "no"},
])
def test_validate_audit_rejects(bad):
    with pytest.raises(schemas.SchemaError):
        schemas.validate_audit(bad)


def test_make_validate_target_profile():
    p = schemas.make_target_profile("acme.com", tech_stack=["NGINX", "aws"], endpoints=["/api"], notes="prod")
    assert p["type"] == "target_profile" and p["tech_stack"] == ["aws", "nginx"]
    schemas.validate_target_profile(p)
    with pytest.raises(schemas.SchemaError):
        schemas.validate_target_profile({"type": "target_profile", "schema_version": 1, "tech_stack": [1]})


def test_audit_written_to_sibling_not_patterns(tmp_path):
    db = str(tmp_path / "p.jsonl")
    pdb.record(pat(), db)                                   # a pattern
    pdb.record(schemas.make_audit("write", "record", target="acme.com"), db)  # an audit -> sibling
    assert len(pdb.load(db)) == 1                           # patterns.jsonl has ONLY the pattern
    assert (tmp_path / "audit.jsonl").is_file()
    audit_lines = [l for l in (tmp_path / "audit.jsonl").read_text().splitlines() if l.strip()]
    assert audit_lines and json.loads(audit_lines[0])["type"] == "audit"


def test_profile_routed_to_profiles_file_and_recalled(tmp_path):
    db = str(tmp_path / "p.jsonl")
    pdb.record(schemas.make_target_profile("acme.com", tech_stack=["nginx"], ts=1.0), db)
    pdb.record(schemas.make_target_profile("acme.com", tech_stack=["nginx", "aws"], ts=2.0), db)
    assert (tmp_path / "profiles.jsonl").is_file()
    assert pdb.load(db) == []                               # profiles do NOT pollute pattern recall
    prof = pdb.recall_profile("acme.com", db)
    assert prof["ts"] == 2.0 and "aws" in prof["tech_stack"]   # newest


def test_maybe_gc_triggers_only_over_threshold_and_preserves(tmp_path):
    db = str(tmp_path / "p.jsonl")
    for ts in range(5):
        pdb.record(pat(cvss=9.1, ts=ts), db)                # 5 dupes (same key)
    assert rotation.maybe_gc(db, max_records=100) is None   # under threshold -> no-op
    res = rotation.maybe_gc(db, max_records=3)              # over -> compact
    assert res and res["compacted"] and res["after"] == 1
    assert pdb.load(db)[0]["count"] == 5                    # knowledge preserved, not discarded


def test_record_autogc_via_env(tmp_path, monkeypatch):
    monkeypatch.setenv("ENGAGEMENT_DB_MAX_RECORDS", "3")
    db = str(tmp_path / "p.jsonl")
    for ts in range(4):
        pdb.record(pat(cvss=9.1, ts=ts), db)                # 4th record() triggers maybe_gc
    # file compacted to 1 line; merged still has the single key with count summed
    assert len(pdb.load(db)) == 1 and pdb.load(db)[0]["count"] >= 4


def test_rotate_audit_writes_retention_gap(tmp_path):
    ap = str(tmp_path / "audit.jsonl")
    with open(ap, "w", encoding="utf-8") as fh:
        for i in range(50):
            fh.write(json.dumps(schemas.make_audit("read", "match", ts=float(i))) + "\n")
    assert rotation.rotate_audit(ap, max_bytes=10, keep=2) is True
    first = json.loads(open(ap, encoding="utf-8").readline())
    assert first["type"] == "retention_gap" and first["dropped"] >= 0


def test_cli_denial_audited(tmp_path):
    db = str(tmp_path / "p.jsonl")
    # invalid severity -> make_pattern raises -> exit 2 -> a denial audit is written
    assert pdb.main(["--db", db, "record", "--target", "acme.com", "--vuln-class", "ssrf",
                     "--severity", "BOGUS"]) == 2
    audit = [json.loads(l) for l in (tmp_path / "audit.jsonl").read_text().splitlines() if l.strip()]
    assert any(ev["type"] == "audit" and ev["outcome"] == "denial" for ev in audit)


def test_cli_profile_and_audit_stats(tmp_path, capsys):
    db = str(tmp_path / "p.jsonl")
    assert pdb.main(["--db", db, "profile", "--target", "acme.com", "--tech-stack", "nginx,aws"]) == 0
    assert pdb.main(["--db", db, "recall-profile", "--target", "acme.com"]) == 0
    assert "nginx" in capsys.readouterr().out
    assert pdb.main(["--db", db, "record", "--target", "acme.com", "--vuln-class", "ssrf", "--severity", "high"]) == 0
    assert pdb.main(["--db", db, "audit-stats"]) == 0
    out = capsys.readouterr().out
    assert "by outcome" in out and "events:" in out


# ========================================================= PR2: status/decay + BM25 + inject
def test_make_pattern_lifecycle_defaults():
    p = pat()
    assert p["status"] == "active" and p["confidence"] == 1.0 and p["ttl_days"] == 0 and p["last_verified"] == p["ts"]


def test_legacy_record_without_lifecycle_still_loads(tmp_path):
    db = str(tmp_path / "p.jsonl")
    legacy = {"schema_version": 1, "type": "pattern", "ts": 1.0, "target": "acme.com", "tech_stack": [],
              "vuln_class": "ssrf", "cwe": "", "attack_id": "", "technique": "x", "severity": "high",
              "cvss": 7.0, "evidence_ref": "", "source": "", "count": 1}   # no status/confidence/ttl
    Path(db).write_text(json.dumps(legacy) + "\n", encoding="utf-8")
    assert len(pdb.load(db)) == 1
    assert pdb.match(pdb.merged(db), vuln_class="ssrf")[0]["vuln_class"] == "ssrf"   # ranks (defaults active)


def test_rank_confidence_tiebreak():
    a = schemas.make_pattern("a.com", "ssrf", severity="high", cvss=7.0, confidence=0.9, ts=1)
    b = schemas.make_pattern("b.com", "ssrf", severity="high", cvss=7.0, confidence=0.4, ts=1)
    assert schemas.rank_score(a) > schemas.rank_score(b)


def test_merge_recency_wins_status():
    old = schemas.make_pattern("a.com", "ssrf", technique="t", status="active", ts=10, last_verified=10)
    new = schemas.make_pattern("a.com", "ssrf", technique="t", status="deprecated", ts=20, last_verified=20)
    assert schemas.merge(old, new)["status"] == "deprecated"     # newer decision wins
    assert schemas.merge(new, old)["status"] == "deprecated"     # order-independent


def test_pattern_id_stable_by_key():
    assert schemas.pattern_id(pat()) == schemas.pattern_id(pat(target="ACME.com."))


def test_bm25_within_severity_beats_cvss(tmp_path):
    db = str(tmp_path / "p.jsonl")
    pdb.record(schemas.make_pattern("a.com", "ssrf", technique="dns rebinding ttl", severity="high", cvss=8.0, ts=1), db)
    pdb.record(schemas.make_pattern("a.com", "ssrf", technique="imds metadata theft", severity="high", cvss=7.0, ts=2), db)
    hits = pdb.match(pdb.merged(db), vuln_class="ssrf", query="imds metadata")
    assert "metadata" in hits[0]["technique"]    # same severity -> relevance beats higher CVSS


def test_alias_query_match(tmp_path):
    db = str(tmp_path / "p.jsonl")
    pdb.record(schemas.make_pattern("a.com", "ssrf", technique="metadata service credential read", severity="high", cvss=7.0, ts=1), db)
    pdb.record(schemas.make_pattern("a.com", "ssrf", technique="port scan probe", severity="high", cvss=7.0, ts=2), db)
    hits = pdb.match(pdb.merged(db), vuln_class="ssrf", query="imds")   # imds alias -> metadata
    assert "metadata" in hits[0]["technique"]


def test_status_filter(tmp_path):
    db = str(tmp_path / "p.jsonl")
    pdb.record(schemas.make_pattern("a.com", "ssrf", technique="a", status="active", ts=1), db)
    pdb.record(schemas.make_pattern("a.com", "ssrf", technique="b", status="deprecated", ts=2, last_verified=2), db)
    default = pdb.match(pdb.merged(db), vuln_class="ssrf")
    assert all(h["status"] != "deprecated" for h in default)         # deprecated excluded by default
    assert pdb.match(pdb.merged(db), vuln_class="ssrf", status="deprecated")  # explicit includes it


def test_ttl_staleness_downranks(tmp_path):
    db = str(tmp_path / "p.jsonl")
    pdb.record(schemas.make_pattern("a.com", "ssrf", technique="old", severity="critical", cvss=9.0,
                                    ttl_days=30, ts=1000, last_verified=1000), db)
    pdb.record(schemas.make_pattern("a.com", "ssrf", technique="fresh", severity="low", cvss=2.0,
                                    ttl_days=0, ts=2000, last_verified=2000), db)
    recs = pdb.merged(db, now=1000 + 31 * 86400)                     # 31 days later
    assert [r for r in recs if r["technique"] == "old"][0]["status"] == "stale"
    assert pdb.match(recs, vuln_class="ssrf")[0]["technique"] == "fresh"   # active beats stale despite impact


def test_inject_budget_modes_sentinel(tmp_path, capsys, monkeypatch):
    db = str(tmp_path / "p.jsonl")
    for i in range(6):
        pdb.record(schemas.make_pattern("a.com", "ssrf", technique=f"technique number {i}", severity="high", cvss=9.0, ts=i), db)
    assert pdb.main(["--db", db, "inject", "--vuln-class", "ssrf", "--max-bytes", "120"]) == 0
    assert len(capsys.readouterr().out) < 400                        # byte budget truncates
    monkeypatch.setenv("ENGAGEMENT_MEMORY_MODE", "off")
    assert pdb.main(["--db", db, "inject", "--vuln-class", "ssrf"]) == 0
    assert capsys.readouterr().out.strip() == ""                     # off mode suppresses
    monkeypatch.delenv("ENGAGEMENT_MEMORY_MODE", raising=False)
    assert pdb.main(["--db", db, "inject", "--vuln-class", "nope"]) == 0
    assert "no prior intel" in capsys.readouterr().out               # low-signal sentinel


def test_cli_promote_deprecate(tmp_path, capsys):
    db = str(tmp_path / "p.jsonl")
    pdb.record(schemas.make_pattern("acme.com", "ssrf", technique="metadata", severity="high", cvss=9.0, ts=1, last_verified=1), db)
    assert pdb.match(pdb.merged(db), vuln_class="ssrf")
    assert pdb.main(["--db", db, "deprecate", "--target", "acme.com", "--vuln-class", "ssrf", "--technique", "metadata"]) == 0
    assert not pdb.match(pdb.merged(db), vuln_class="ssrf")           # excluded after deprecate
    assert pdb.main(["--db", db, "promote", "--target", "acme.com", "--vuln-class", "ssrf", "--technique", "metadata"]) == 0
    assert pdb.match(pdb.merged(db), vuln_class="ssrf")               # back after promote


# ========================================================= PR3: secret guard + review + global
@pytest.mark.parametrize("val", [
    "password=hunter2longvalue", _fixture("-----BEGIN ", "RSA PRIVATE KEY-----"),
    _fixture("AKIA", "IOSFODNN7EXAMPLE"), _fixture("ghp_", "abcdefghij0123456789klmnop"),
    _fixture("eyJ", "hbGciOiJIUzI1NiJ9.payloadpart"),
])
def test_secret_guard_rejects_inline_secret(val):
    with pytest.raises(schemas.SchemaError):
        schemas.make_pattern("a.com", "ssrf", evidence_ref=val)
    with pytest.raises(schemas.SchemaError):
        schemas.make_pattern("a.com", "ssrf", source=val)


def test_secret_guard_allows_paths():
    schemas.make_pattern("a.com", "ssrf", evidence_ref="evidence/logs/FIND-001.txt", source="burp-repeater")


def test_review_gated_record_collision(tmp_path, capsys):
    db = str(tmp_path / "p.jsonl")
    assert pdb.main(["--db", db, "record", "--target", "acme.com", "--vuln-class", "ssrf",
                     "--technique", "metadata", "--severity", "high"]) == 0
    capsys.readouterr()
    n_before = len([x for x in Path(db).read_text().splitlines() if x.strip()])
    # same key, no --resolve -> review_required, NOT written
    assert pdb.main(["--db", db, "record", "--target", "acme.com", "--vuln-class", "ssrf",
                     "--technique", "metadata", "--severity", "critical"]) == 0
    assert "review_required" in capsys.readouterr().out
    assert len([x for x in Path(db).read_text().splitlines() if x.strip()]) == n_before
    # with --resolve update -> written
    assert pdb.main(["--db", db, "record", "--target", "acme.com", "--vuln-class", "ssrf",
                     "--technique", "metadata", "--severity", "critical", "--resolve", "update"]) == 0
    assert len([x for x in Path(db).read_text().splitlines() if x.strip()]) > n_before


def test_review_reject_excludes_from_recall(tmp_path):
    db = str(tmp_path / "p.jsonl")
    pdb.record(schemas.make_pattern("acme.com", "ssrf", technique="metadata", severity="high", ts=1, last_verified=1), db)
    assert pdb.main(["--db", db, "record", "--target", "acme.com", "--vuln-class", "ssrf",
                     "--technique", "metadata", "--resolve", "reject", "--reason", "false positive"]) == 0
    assert not pdb.match(pdb.merged(db), vuln_class="ssrf")           # rejected (recency) -> excluded


def test_global_scope_sanitized_and_isolated(tmp_path, monkeypatch):
    db = str(tmp_path / "p.jsonl")
    monkeypatch.setenv("ENGAGEMENT_GLOBAL_DB", str(tmp_path / "global.jsonl"))
    assert pdb.main(["--db", db, "record", "--target", "acme.com", "--vuln-class", "ssrf",
                     "--technique", "metadata", "--severity", "high", "--evidence-ref", "logs/x.txt", "--global"]) == 0
    g = [json.loads(x) for x in Path(tmp_path / "global.jsonl").read_text().splitlines() if x.strip()]
    assert g and g[0]["target"] == "global" and g[0]["evidence_ref"] == "" and g[0]["technique"] == "metadata"
    # local recall is isolated from global; --include-global merges it in
    local_only = pdb.match(pdb.merged(db), vuln_class="ssrf")
    assert local_only and all(h["target"] == "acme.com" for h in local_only)
    with_global = pdb.match(pdb.merged(db) + pdb.merged(pdb.global_db()), vuln_class="ssrf")
    assert any(h["target"] == "global" for h in with_global)


def test_cli_match_include_global(tmp_path, monkeypatch, capsys):
    db = str(tmp_path / "p.jsonl")
    monkeypatch.setenv("ENGAGEMENT_GLOBAL_DB", str(tmp_path / "global.jsonl"))
    pdb.record(_sanitize := pdb._sanitize_for_global(schemas.make_pattern("x", "ssrf", technique="imds", severity="high")), pdb.global_db())
    assert pdb.main(["--db", db, "match", "--vuln-class", "ssrf", "--include-global", "--json"]) == 0
    assert "imds" in capsys.readouterr().out


# ========================================================= red-team hardening (secret guard depth + scrub)
@pytest.mark.parametrize("val", [
    _fixture("wJalrXUtnFEMI/K7MDENG/", "bPxRfiCYEXAMPLEKEY"),           # AWS 40-char secret access key
    _fixture("mysql://root:", "SuperSecretPass@db.internal:3306/prod"), # connection string w/ password
    _fixture("postgres://admin:", "hunter2hunter2@10.0.0.5:5432/app"),
    _fixture("sk_", "live_51H8xY2eZvKYlo2C0abcdefghijklmnopqrstuv"),    # stripe
    _fixture("AIza", "SyB1a2b3c4d5e6f7g8h9i0jklmnopqrstuvwx"),          # google api key
    _fixture("ya29.", "a0AfB12345abcdef67890ghijklmnop"),              # google oauth
    _fixture("https://hooks.slack.com/services/", "T01ABCDEF/B01ABCDEF/XXXXXXXXXXXXXXXXXXXXXXXX"),
    _fixture("Authorization Bearer ", "abcdef0123456789ABCDEF0123456789xyzqQ"),  # bearer token value
    "Zx9Kq2Lm7Pw4Rt6Yv1Bn3Cf5Dg8Hj0Ik2Ol4Mp6Qr8St0UvWx",             # unprefixed high-entropy blob
])
def test_secret_guard_catches_more_classes(val):
    assert schemas.looks_like_secret(val) is True


def test_secret_guard_scans_all_persisted_fields():
    with pytest.raises(schemas.SchemaError):                            # technique
        schemas.make_pattern("acme.com", "ssrf", technique="exfil via " + _fixture("wJalrXUtnFEMI/K7MDENG/", "bPxRfiCYEXAMPLEKEY"))
    with pytest.raises(schemas.SchemaError):                            # target_profile.notes
        schemas.make_target_profile("acme.com", notes="root password=Sup3rS3cretValue123")
    with pytest.raises(schemas.SchemaError):                            # audit.note
        schemas.make_audit("write", "x", note="grabbed token=" + _fixture("ghp_", "16C7e42F292c6912E7710c838347Ae178B4aZZ"))


@pytest.mark.parametrize("val", [
    "password: weak policy observed (min 4 chars)",                    # documentary prose
    "api_key=REDACTED reflected in response",                          # placeholder value
    "default password=admin",                                          # short/weak, documentary
    "evidence/logs/findings/FIND-001-metadata-theft-poc",              # long path, low entropy
])
def test_secret_guard_allows_documentary_prose(val):
    assert schemas.looks_like_secret(val) is False


def test_global_scrub_removes_client_target_from_technique():
    rec = schemas.make_pattern("acme-internal.corp.local", "ssrf",
                               technique="metadata theft via acme-internal.corp.local proxy", severity="high")
    san = pdb._sanitize_for_global(rec)
    assert "acme-internal" not in san["technique"] and san["target"] == "global"
    assert san["evidence_ref"] == "" and san["source"] == ""


def test_pattern_key_whitespace_normalized():
    a = schemas.pattern_key({"target": "a.com", "vuln_class": "ssrf", "technique": "metadata   theft"})
    b = schemas.pattern_key({"target": "a.com", "vuln_class": "ssrf", "technique": "metadata theft"})
    assert a == b


# ========================================================= adversarial regressions
def _poison_db(tmp_path):
    """A db with one valid record + a battery of type-poisoned (schema-valid-looking) lines."""
    good = pat(cvss=9.1, ts=1)
    base = dict(good)
    lines = [
        json.dumps(good),
        json.dumps({**base, "count": [1, 2]}),          # count as list
        json.dumps({**base, "tech_stack": [["x"]]}),    # nested-list element
        json.dumps({**base, "ts": "not-a-number"}),     # non-numeric ts
        json.dumps({**base, "schema_version": True}),   # bool masquerading as 1
        json.dumps({**base, "schema_version": 1.0}),    # float masquerading as 1
        "this is not json",                              # invalid json
    ]
    p = tmp_path / "p.jsonl"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(p)


def test_regression_poisoned_records_skipped_at_load(tmp_path):
    db = _poison_db(tmp_path)
    assert len(pdb.load(db)) == 1                       # only the valid record survives


def test_regression_poison_does_not_crash_match_compact_stats(tmp_path, capsys):
    db = _poison_db(tmp_path)
    assert pdb.match(pdb.merged(db), vuln_class="ssrf")  # no crash, returns the valid one
    assert pdb.main(["--db", db, "match", "--vuln-class", "ssrf"]) == 0
    assert pdb.main(["--db", db, "compact"]) == 0
    assert pdb.main(["--db", db, "stats"]) == 0
    assert len(pdb.load(db)) == 1                       # compaction preserved the valid record


def test_regression_critical_without_cvss_ranks_above_scored_low():
    crit = schemas.make_pattern("a.com", "rce", severity="critical", cvss=None, ts=1)
    low = schemas.make_pattern("b.com", "xss", severity="low", cvss=5.0, ts=2)
    ranked = pdb.match([low, crit], top=10)
    assert ranked[0]["severity"] == "critical"          # severity dominates a missing CVSS


@pytest.mark.parametrize("bad_sv", [True, 1.0])
def test_regression_schema_version_type_strict(bad_sv):
    rec = dict(pat()); rec["schema_version"] = bad_sv
    with pytest.raises(schemas.SchemaError):
        schemas.validate_pattern(rec)


def test_regression_case_insensitive_vuln_class_recall():
    # a foreign/hand-written valid record with uppercase class must still be recalled by 'ssrf'
    rec = dict(pat()); rec["vuln_class"] = "SSRF"
    schemas.validate_pattern(rec)                        # uppercase is a valid string
    assert pdb.match([rec], vuln_class="ssrf")           # matched case-insensitively
