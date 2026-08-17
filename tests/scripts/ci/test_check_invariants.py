"""Tests for scripts/ci/check_invariants.py — the safety-substring drift canary.

Two properties matter: (1) it passes GREEN on the real repo tree (the invariants are
actually consistent right now), and (2) it goes RED and names the exact (file, phrase)
when a copy drifts. We test the second against a temp copy so we never mutate the repo.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts" / "ci"))

import check_invariants as ci  # noqa: E402

_REPO = Path(__file__).resolve().parents[3]


def test_real_tree_is_consistent():
    # The canary must be green on the tree it ships with, else it's crying wolf.
    assert ci.check(_REPO) == []


def test_cli_green_on_real_tree():
    assert ci.main(["--root", str(_REPO)]) == 0


def test_planted_drift_is_caught(tmp_path):
    # Minimal fake tree with ONE invariant across two files, one of which drifted.
    (tmp_path / "CLAUDE.md").write_text("... a status code is not impact ...", encoding="utf-8")
    ref = tmp_path / "skills" / "references"
    ref.mkdir(parents=True)
    (ref / "finding-evidence-standards.md").write_text("softened wording here", encoding="utf-8")

    invariants = [{
        "id": "status-code-not-impact",
        "text": "a status code is not impact",
        "files": ["CLAUDE.md", "skills/references/finding-evidence-standards.md"],
    }]
    drifts = ci.check(tmp_path, invariants)
    assert len(drifts) == 1
    d = drifts[0]
    assert d.invariant == "status-code-not-impact"
    assert d.file == "skills/references/finding-evidence-standards.md"
    assert d.problem == "missing"


def test_unreadable_file_is_reported(tmp_path):
    (tmp_path / "CLAUDE.md").write_text("a status code is not impact", encoding="utf-8")
    invariants = [{
        "id": "x", "text": "a status code is not impact",
        "files": ["CLAUDE.md", "does/not/exist.md"],
    }]
    drifts = ci.check(tmp_path, invariants)
    assert [d.problem for d in drifts] == ["unreadable"]


def test_cli_exit_1_on_drift(tmp_path, monkeypatch):
    (tmp_path / "CLAUDE.md").write_text("nothing here", encoding="utf-8")
    monkeypatch.setattr(ci, "INVARIANTS", [{
        "id": "x", "text": "a status code is not impact", "files": ["CLAUDE.md"],
    }])
    assert ci.main(["--root", str(tmp_path)]) == 1


def test_cli_json_output(tmp_path, capsys, monkeypatch):
    (tmp_path / "CLAUDE.md").write_text("nothing", encoding="utf-8")
    monkeypatch.setattr(ci, "INVARIANTS", [{
        "id": "x", "text": "missing phrase", "files": ["CLAUDE.md"],
    }])
    ci.main(["--root", str(tmp_path), "--json"])
    import json
    out = json.loads(capsys.readouterr().out)
    assert out[0]["invariant"] == "x"
    assert out[0]["problem"] == "missing"
