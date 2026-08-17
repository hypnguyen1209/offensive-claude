"""Tests for scripts/ci/verify_skills_lock.py — the skill-tree lockfile.

Real tree matches its committed lock; a content change / add / remove is caught; the digest
is deterministic and ignores pyc/__pycache__; --update round-trips.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts" / "ci"))

import verify_skills_lock as vsl  # noqa: E402

_REPO = Path(__file__).resolve().parents[3]


def _make_skill(root, name, files):
    d = root / "skills" / name
    d.mkdir(parents=True)
    for rel, content in files.items():
        f = d / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(content, encoding="utf-8")
    return d


# ------------------------------------------------------------------ real tree
def test_real_tree_matches_committed_lock():
    # The shipped skills-lock.json must match the shipped tree, else CI would be red on main.
    assert vsl.main(["--root", str(_REPO)]) == 0


def test_committed_lock_covers_all_skill_dirs():
    lock = json.loads((_REPO / "skills-lock.json").read_text(encoding="utf-8"))
    on_disk = {d.name for d in (_REPO / "skills").iterdir()
               if d.is_dir() and (d / "SKILL.md").is_file()}
    assert set(lock["skills"]) == on_disk


# ------------------------------------------------------------------ digest properties
def test_digest_is_deterministic(tmp_path):
    _make_skill(tmp_path, "s", {"SKILL.md": "router", "references/a.md": "x"})
    d1 = vsl._dir_digest(tmp_path / "skills" / "s")
    d2 = vsl._dir_digest(tmp_path / "skills" / "s")
    assert d1 == d2


def test_digest_ignores_pycache(tmp_path):
    sd = _make_skill(tmp_path, "s", {"SKILL.md": "router", "scripts/x.py": "print(1)"})
    before = vsl._dir_digest(sd)
    (sd / "scripts" / "__pycache__").mkdir()
    (sd / "scripts" / "__pycache__" / "x.cpython.pyc").write_bytes(b"\x00\x01")
    (sd / "scripts" / "x.pyo").write_bytes(b"\x00")
    assert vsl._dir_digest(sd) == before


def test_content_change_changes_digest(tmp_path):
    sd = _make_skill(tmp_path, "s", {"SKILL.md": "router"})
    before = vsl._dir_digest(sd)
    (sd / "SKILL.md").write_text("router EDITED", encoding="utf-8")
    assert vsl._dir_digest(sd) != before


# ------------------------------------------------------------------ diff / drift
def test_changed_skill_is_flagged(tmp_path):
    _make_skill(tmp_path, "s", {"SKILL.md": "v1"})
    vsl.main(["--root", str(tmp_path), "--update"])
    (tmp_path / "skills" / "s" / "SKILL.md").write_text("v2", encoding="utf-8")
    assert vsl.main(["--root", str(tmp_path)]) == 1


def test_added_and_removed_skills_flagged(tmp_path):
    _make_skill(tmp_path, "a", {"SKILL.md": "x"})
    recorded = vsl.compute_lock(tmp_path)
    _make_skill(tmp_path, "b", {"SKILL.md": "y"})           # added
    (tmp_path / "skills" / "a" / "SKILL.md").unlink()
    (tmp_path / "skills" / "a").rmdir()                     # removed
    current = vsl.compute_lock(tmp_path)
    drifts = {d.skill: d.problem for d in vsl.diff_lock(recorded, current)}
    assert drifts == {"a": "removed", "b": "added"}


def test_dir_without_skill_md_is_excluded(tmp_path):
    _make_skill(tmp_path, "real", {"SKILL.md": "x"})
    (tmp_path / "skills" / "references").mkdir()
    (tmp_path / "skills" / "references" / "shared.md").write_text("z", encoding="utf-8")
    lock = vsl.compute_lock(tmp_path)
    assert set(lock["skills"]) == {"real"}


def test_update_round_trips(tmp_path):
    _make_skill(tmp_path, "s", {"SKILL.md": "x", "references/r.md": "y"})
    assert vsl.main(["--root", str(tmp_path), "--update"]) == 0
    assert (tmp_path / "skills-lock.json").is_file()
    assert vsl.main(["--root", str(tmp_path)]) == 0


def test_missing_lock_returns_2(tmp_path):
    _make_skill(tmp_path, "s", {"SKILL.md": "x"})
    assert vsl.main(["--root", str(tmp_path)]) == 2  # no lock, not --update
