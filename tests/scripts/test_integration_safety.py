"""End-to-end integration: the safety stack composes as a pipeline.

scope.json -> scope_guard -> action_guard -> validate_findings -> engagement-memory -> engine,
plus boundary redaction. Proves the Phase 1-3 components work together, not just in isolation.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for p in [ROOT / "skills" / "coding-mastery" / "scripts" / "_lib",
          ROOT / "skills" / "vulnerability-analysis" / "scripts",
          ROOT / "skills" / "engagement-memory" / "scripts",
          ROOT / "engine"]:
    sys.path.insert(0, str(p))

import scope_guard as sg          # noqa: E402
import action_guard as ag         # noqa: E402
import validate_findings as vf    # noqa: E402
import schemas, pattern_db as pdb  # noqa: E402
import redact_headers as rh       # noqa: E402
import budget as bd, tracer as tr, engine as eng  # noqa: E402

SECRET = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.s1gnatureVALUE"


def test_safety_stack_end_to_end(tmp_path):
    # 1) machine-readable scope, enforced like an HTTP client
    sf = tmp_path / "scope.json"
    sf.write_text(json.dumps({"engagement": "E", "in_scope": ["acme.com", "*.acme.com"],
                              "out_of_scope": ["dev.acme.com"]}), encoding="utf-8")
    scope = sg.Scope.load(str(sf))
    assert scope.evaluate("api.acme.com").in_scope is True
    assert scope.evaluate("dev.acme.com").in_scope is False
    assert scope.evaluate("acme.com:80@evil.com").in_scope is False     # userinfo -> evil.com

    # 2) action guard consults the same scope + safe-method policy
    g = ag.ActionGuard(scope)
    assert g.decide("GET", "api.acme.com").action == ag.ALLOW
    assert g.decide("POST", "api.acme.com").action == ag.REQUIRE_APPROVAL
    assert g.decide("GET", "dev.acme.com").action == ag.BLOCK

    # 3) a finding is CONFIRMED only with grounded evidence + structured proof
    ev = tmp_path / "f1.txt"; ev.write_text("169.254.169.254 metadata response body", encoding="utf-8")
    finding = {"id": "F1", "title": "SSRF in webhook", "cwe": "CWE-918", "severity": "High",
               "target": "api.acme.com", "evidence": [str(ev)], "proof": {"internal_response_read": True}}
    assert vf.evaluate_finding(finding, None).tier == "CONFIRMED"
    # the same finding without the proof signal can't be confirmed
    assert vf.evaluate_finding({**finding, "proof": {}}, None).tier == "POSSIBLE"

    # 4) the confirmed finding is learned, then recalled for the next engagement
    db = str(tmp_path / "patterns.jsonl")
    pdb.record(schemas.make_pattern("api.acme.com", "ssrf", cwe="CWE-918", attack_id="T1190",
                                    severity="high", cvss=9.1, tech_stack=["nginx", "aws"], ts=1.0), db)
    hits = pdb.match(pdb.merged(db), vuln_class="ssrf", tech_stack=["aws"])
    assert hits and hits[0]["attack_id"] == "T1190"

    # 5) captured traffic is redacted at the boundary
    raw = f"GET / HTTP/1.1\r\nHost: api.acme.com\r\nAuthorization: Bearer {SECRET}\r\n\r\n"
    assert SECRET not in rh.redact_text(raw)

    # 6) the engine runs an in-scope plan to completion...
    box = {"t": 0.0}; clk = (lambda: box["t"])
    plan_ok = [{"id": "scope_check", "action": "scope_check", "phase": "scope", "target": "api.acme.com", "always": True},
               {"id": "note", "action": "note", "phase": "recon", "text": "proceed"}]
    e_ok = eng.Engine(plan_ok, tracer=tr.Tracer(str(tmp_path / "t_ok.jsonl")),
                      budget=bd.Budget(min_steps=1, max_seconds=1e9, clock=clk), scope=scope, target="api.acme.com")
    assert e_ok.run()["finished"] is True

    # ...and HALTS an out-of-scope plan at the gate (the whole point)
    plan_oos = [{"id": "scope_check", "action": "scope_check", "phase": "scope", "target": "dev.acme.com", "always": True}]
    e_oos = eng.Engine(plan_oos, tracer=tr.Tracer(str(tmp_path / "t_oos.jsonl")),
                       budget=bd.Budget(min_steps=1, max_seconds=1e9, clock=clk), scope=scope, target="dev.acme.com")
    s = e_oos.run()
    assert s["finished"] is False and "scope violation" in (s["halted"] or "")
