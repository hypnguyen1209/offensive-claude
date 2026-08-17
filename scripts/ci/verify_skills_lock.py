#!/usr/bin/env python3
"""verify_skills_lock.py - tamper-evident lock over the skill tree.

Ports the idea of a lockfile (repomix/claude-mem pin their manifests): the plugin ships ~37 skills
that a model loads and trusts. This computes a deterministic SHA-256 *directory digest* for each
`skills/<name>/` (every file under it, path-sorted) and pins it in `skills-lock.json`. CI then
recomputes and fails if any skill's content drifted, a skill was added, or one was removed - so an
unreviewed edit to a load-bearing SKILL.md / reference / script cannot land silently.

This is integrity, not authenticity - it catches accidental/unreviewed drift and obvious tampering
in the working tree, not a determined attacker who also edits the lockfile. Review the lockfile diff.

CLI:
  verify_skills_lock.py                 # exit 1 on any drift, 0 if lock matches tree, 2 on error
  verify_skills_lock.py --json
  verify_skills_lock.py --update        # regenerate skills-lock.json from the current tree
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

_ROOT = Path(__file__).resolve().parents[2]
_SKILLS_DIR = "skills"
_LOCK = "skills-lock.json"
_LOCK_VERSION = 1
_CHUNK = 1 << 16
# files that are build artifacts / not content - excluded so the digest is reproducible
_IGNORE_DIRS = {"__pycache__", ".git", ".pytest_cache"}
_IGNORE_SUFFIXES = {".pyc", ".pyo"}


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def _dir_digest(skill_dir: Path) -> str:
    """Deterministic digest over all content files under skill_dir.

    Hash = sha256 of the sorted lines "<relposix>\\0<filehash>\\n". Sorting + posix separators makes
    it stable across OSes; ignoring pyc/__pycache__ makes it reproducible regardless of import state.
    """
    entries: list[str] = []
    for p in sorted(skill_dir.rglob("*")):
        if not p.is_file():
            continue
        if any(part in _IGNORE_DIRS for part in p.relative_to(skill_dir).parts):
            continue
        if p.suffix in _IGNORE_SUFFIXES:
            continue
        rel = p.relative_to(skill_dir).as_posix()
        entries.append(f"{rel}\0{_sha256_file(p)}\n")
    h = hashlib.sha256()
    for line in sorted(entries):
        h.update(line.encode("utf-8"))
    return h.hexdigest()


def compute_lock(root: Optional[Path] = None) -> dict:
    root = Path(root) if root else _ROOT
    skills_root = root / _SKILLS_DIR
    skills: dict[str, dict] = {}
    for d in sorted(skills_root.iterdir()):
        if not d.is_dir() or d.name in _IGNORE_DIRS:
            continue
        if not (d / "SKILL.md").is_file():
            continue  # shared dirs (e.g. references/) are not skills
        skills[d.name] = {"path": f"{_SKILLS_DIR}/{d.name}", "sha256": _dir_digest(d)}
    return {"version": _LOCK_VERSION, "skills": skills}


@dataclass
class Drift:
    skill: str
    problem: str          # "added" | "removed" | "changed"

    def to_dict(self) -> dict:
        return {"skill": self.skill, "problem": self.problem}


def diff_lock(recorded: dict, current: dict) -> list[Drift]:
    rec = recorded.get("skills", {})
    cur = current.get("skills", {})
    drifts: list[Drift] = []
    for name in sorted(set(rec) | set(cur)):
        if name not in rec:
            drifts.append(Drift(name, "added"))
        elif name not in cur:
            drifts.append(Drift(name, "removed"))
        elif rec[name].get("sha256") != cur[name].get("sha256"):
            drifts.append(Drift(name, "changed"))
    return drifts


def _load_lock(root: Path) -> dict:
    return json.loads((root / _LOCK).read_text(encoding="utf-8"))


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Verify (or regenerate) the skill-tree lockfile.")
    p.add_argument("--json", action="store_true")
    p.add_argument("--root")
    p.add_argument("--update", action="store_true", help="regenerate skills-lock.json from the tree")
    args = p.parse_args(argv)
    root = Path(args.root) if args.root else _ROOT
    try:
        current = compute_lock(root)
        if args.update:
            (root / _LOCK).write_text(json.dumps(current, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(f"wrote {_LOCK}: {len(current['skills'])} skills locked")
            return 0
        recorded = _load_lock(root)
    except FileNotFoundError:
        print(f"error: {_LOCK} not found - run with --update to create it", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    drifts = diff_lock(recorded, current)
    if args.json:
        print(json.dumps([d.to_dict() for d in drifts], indent=2))
    else:
        if not drifts:
            print(f"ok: {len(current['skills'])} skills match {_LOCK}")
        else:
            for d in drifts:
                print(f"DRIFT {d.problem}: {d.skill}")
            print("(review the change, then run --update to re-pin)", file=sys.stderr)
    return 1 if drifts else 0


if __name__ == "__main__":
    raise SystemExit(main())
