#!/usr/bin/env python3
"""check_invariants.py - drift canary for load-bearing SAFETY substrings.

Ports the idea of ponytail's `check-rule-copies.js`: a small pinned set of safety-critical
phrases must survive **verbatim** across every file that is supposed to carry them. The plugin
keeps the same rule in several places on purpose (CLAUDE.md doctrine, the human-readable
references, and the enforcing script's messages) so a model reading any one of them gets the
same contract. The failure mode this catches: someone edits ONE copy (softening "a status code
is not impact", dropping the IDOR "another principal's data" bar) and the others silently drift.

This is NOT a general spell-checker - it asserts a curated invariant list, so a green run means
"the load-bearing safety language is still consistent across its copies", and a red run names the
exact (file, phrase) that drifted.

CLI:
  check_invariants.py                 # exit 1 if any invariant drifted, 0 if consistent
  check_invariants.py --json
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# repo root = two levels up from scripts/ci/
_ROOT = Path(__file__).resolve().parents[2]

# Each invariant: a load-bearing safety substring that MUST appear verbatim in every listed file.
# Keep phrases lowercase-stable and free of markdown bold so the same literal matches prose and code.
INVARIANTS: list[dict] = [
    {
        "id": "status-code-not-impact",
        "text": "a status code is not impact",
        "files": ["CLAUDE.md", "skills/references/finding-evidence-standards.md"],
    },
    {
        "id": "idor-cross-principal",
        "text": "another principal's data",
        "files": ["CLAUDE.md", "skills/vulnerability-analysis/scripts/validate_findings.py"],
    },
    {
        "id": "rce-command-output",
        "text": "command output",
        "files": [
            "CLAUDE.md",
            "skills/references/finding-validation-runtime.md",
            "skills/vulnerability-analysis/scripts/validate_findings.py",
        ],
    },
    {
        "id": "confidence-quote-grounded",
        "text": "a direct quote",
        "files": ["CLAUDE.md", "agents/security-reviewer.md", "agents/reverse-engineer.md"],
    },
    {
        "id": "scope-guard-enforced",
        "text": "scope_guard.py",
        "files": [
            "CLAUDE.md",
            "agents/redteam-planner.md",
            "agents/exploit-researcher.md",
            "agents/security-reviewer.md",
            "agents/reverse-engineer.md",
            "agents/ai-researcher.md",
            "agents/network-analyst.md",
        ],
    },
    {
        "id": "tier-vocabulary",
        "text": "POSSIBLE",
        "files": [
            "CLAUDE.md",
            "skills/references/finding-validation-runtime.md",
            "skills/vulnerability-analysis/scripts/validate_findings.py",
        ],
    },
]


@dataclass
class Drift:
    invariant: str
    text: str
    file: str
    problem: str          # "missing" | "unreadable"

    def to_dict(self) -> dict:
        return {"invariant": self.invariant, "text": self.text, "file": self.file, "problem": self.problem}


def check(root: Optional[Path] = None, invariants: Optional[list[dict]] = None) -> list[Drift]:
    """Return a list of drifts (empty = all invariants consistent)."""
    root = Path(root) if root else _ROOT
    invariants = invariants if invariants is not None else INVARIANTS
    drifts: list[Drift] = []
    # cache file reads
    cache: dict[str, Optional[str]] = {}

    def read(rel: str) -> Optional[str]:
        if rel not in cache:
            p = root / rel
            try:
                cache[rel] = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                cache[rel] = None
        return cache[rel]

    for inv in invariants:
        for rel in inv["files"]:
            content = read(rel)
            if content is None:
                drifts.append(Drift(inv["id"], inv["text"], rel, "unreadable"))
            elif inv["text"] not in content:
                drifts.append(Drift(inv["id"], inv["text"], rel, "missing"))
    return drifts


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Assert load-bearing safety substrings are consistent across copies.")
    p.add_argument("--json", action="store_true")
    p.add_argument("--root", help="repo root (default: inferred from this file's location)")
    args = p.parse_args(argv)
    try:
        drifts = check(Path(args.root) if args.root else None)
    except Exception as exc:  # a canary that crashes must fail LOUD, not pass silently
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps([d.to_dict() for d in drifts], indent=2))
    else:
        if not drifts:
            print(f"ok: {len(INVARIANTS)} safety invariants consistent across all copies")
        else:
            for d in drifts:
                print(f"DRIFT [{d.invariant}] {d.problem}: {d.file!r} lacks {d.text!r}")
    return 1 if drifts else 0


if __name__ == "__main__":
    raise SystemExit(main())
