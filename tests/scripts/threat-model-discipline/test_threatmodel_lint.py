"""Tests for threatmodel_lint - completeness lint + drift detection.

Run: pytest tests/scripts/threat-model-discipline/test_threatmodel_lint.py
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "skills" / "threat-model-discipline" / "scripts"))

import threatmodel_lint as tl  # noqa: E402

COMPLETE = {
    "assets": ["customer PII"],
    "entry_points": ["POST /api/login"],
    "trust_boundaries": ["internet->web"],
    "attck": ["T1190", "T1078.001"],
    "mitigations": ["WAF on /api"],
}


# --------------------------------------------------------- lint
def test_complete_model_passes():
    assert tl.lint(COMPLETE) == []


def test_missing_field_flagged():
    m = dict(COMPLETE); del m["entry_points"]
    issues = tl.lint(m)
    assert any("entry_points" in i for i in issues)


def test_empty_list_flagged():
    m = dict(COMPLETE); m["assets"] = []
    assert any("assets" in i for i in tl.lint(m))


def test_placeholder_entry_flagged():
    for ph in ("TBD", "[fill in]", "TODO", "<asset>", "N/A"):
        m = dict(COMPLETE); m = {**COMPLETE, "assets": [ph]}
        assert any("placeholder" in i for i in tl.lint(m)), ph


def test_bad_attck_id_flagged():
    m = {**COMPLETE, "attck": ["T1190", "not-a-technique"]}
    assert any("attck" in i for i in tl.lint(m))


def test_valid_attck_subtechnique_ok():
    assert tl.lint({**COMPLETE, "attck": ["T1059.007"]}) == []


def test_non_object_model():
    assert tl.lint(["not", "a", "dict"])


# --------------------------------------------------------- drift
def test_no_drift_when_identical():
    rep = tl.drift(COMPLETE, COMPLETE)
    assert rep["has_drift"] is False


def test_new_entry_point_is_drift():
    new = {**COMPLETE, "entry_points": COMPLETE["entry_points"] + ["POST /api/admin"]}
    rep = tl.drift(COMPLETE, new)
    assert rep["has_drift"] is True
    assert "entry_points:POST /api/admin" in rep["unreviewed_surface"]


def test_new_asset_and_boundary_are_drift():
    new = {**COMPLETE, "assets": COMPLETE["assets"] + ["secrets vault"],
           "trust_boundaries": COMPLETE["trust_boundaries"] + ["web->db"]}
    rep = tl.drift(COMPLETE, new)
    assert rep["has_drift"] is True
    assert "assets" in rep["added"] and "trust_boundaries" in rep["added"]


def test_removed_surface_is_not_blocking_drift():
    new = {**COMPLETE, "entry_points": []}   # surface shrank
    rep = tl.drift(COMPLETE, new)
    assert rep["has_drift"] is False         # removal recorded, doesn't block
    assert "entry_points" in rep["removed"]


def test_attck_change_is_not_surface_drift():
    new = {**COMPLETE, "attck": COMPLETE["attck"] + ["T1203"]}
    assert tl.drift(COMPLETE, new)["has_drift"] is False   # attck isn't a drift surface


# --------------------------------------------------------- CLI
def test_cli_lint(tmp_path):
    good = tmp_path / "g.json"; good.write_text(json.dumps(COMPLETE), encoding="utf-8")
    bad = tmp_path / "b.json"; bad.write_text(json.dumps({**COMPLETE, "assets": []}), encoding="utf-8")
    assert tl.main(["lint", str(good)]) == 0
    assert tl.main(["lint", str(bad)]) == 1


def test_cli_drift(tmp_path):
    base = tmp_path / "base.json"; base.write_text(json.dumps(COMPLETE), encoding="utf-8")
    new = {**COMPLETE, "entry_points": COMPLETE["entry_points"] + ["/api/new"]}
    newp = tmp_path / "new.json"; newp.write_text(json.dumps(new), encoding="utf-8")
    assert tl.main(["drift", str(base), str(base)]) == 0
    assert tl.main(["drift", str(base), str(newp)]) == 1


def test_cli_bad_json(tmp_path):
    bad = tmp_path / "x.json"; bad.write_text("{not json", encoding="utf-8")
    assert tl.main(["lint", str(bad)]) == 2


# --------- PR-3b red-team regressions (raptor wjg32ea1y) ---------
def test_regression_nonlist_drift_surface_fails_closed():
    # [6] a drift surface given as a dict/string/number must NOT silently hide added surface
    import pytest as _pytest
    for bad in ({"POST /api/admin": 1}, "POST /api/admin", 42):
        new = {**COMPLETE, "entry_points": bad}
        with _pytest.raises(ValueError):
            tl.drift(COMPLETE, new)


def test_regression_cli_nonlist_drift_exits_2(tmp_path):
    base = tmp_path / "b.json"; base.write_text(json.dumps(COMPLETE), encoding="utf-8")
    bad = tmp_path / "n.json"
    bad.write_text(json.dumps({**COMPLETE, "entry_points": {"hidden": "surface"}}), encoding="utf-8")
    rc = tl.main(["drift", str(base), str(bad)])
    assert rc == 2   # fail-closed (error), never a misleading "no drift" exit 0


# --------- PR-3b second-pass regressions (raptor wt0d3jbeb) ---------
def test_regression_nonstring_item_in_drift_surface_fails_closed():
    # [0] an int 5150 vs baseline str '5150' would str-collide and hide a type-change -> fail closed
    import pytest as _p
    with _p.raises(ValueError):
        tl.drift({**COMPLETE, "entry_points": ["5150"]}, {**COMPLETE, "entry_points": [5150]})


def test_regression_more_placeholder_tokens_flagged():
    # [1] common dead tokens must fail the completeness lint, not pass as content
    for ph in ("FIXME", "PLACEHOLDER", "...", "tba", "tbc", "?", "-", "none", "N/A"):
        assert tl.lint({**COMPLETE, "assets": [ph]}), f"{ph!r} should be flagged"
    # a real entry still passes
    assert tl.lint({**COMPLETE, "assets": ["customer PII in orders DB"]}) == []
