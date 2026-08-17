#!/usr/bin/env python3
"""check_constitution.py - assert every agent states its guardrails (structure, not prose).

Ports the idea of ecc's `agent-instruction-safety.test.js`: the plugin's Output Standards say
"agents must state their boundaries", but prose is not enforcement. This turns it into a gated
assertion - each `agents/*.md` and `CLAUDE.md` must CONTAIN required guardrail patterns, so a new
agent added without a scope boundary or a finding agent added without the evidence bar fails CI.

The check is deliberately lenient about WORDING (any-of groups) and strict about PRESENCE: an agent
may phrase its scope rule many ways, but it must have one. This is a floor, not a style guide.

CLI:
  check_constitution.py            # exit 1 if any required guardrail is missing, 0 if all present
  check_constitution.py --json
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

_ROOT = Path(__file__).resolve().parents[2]

# any-of vocabularies (a file satisfies a group if it contains AT LEAST ONE member)
_SCOPE = [
    "scope_guard", ".engage/scope", "scope.json", "in scope", "In scope",
    "in-scope", "out-of-scope", "out of scope",
]
_GUARDRAIL = [
    "finding-evidence-standards", "evidence bar", "[CONFIRMED]", "CONFIRMED",
    "OPSEC", "opsec", "TERMS.md", "authorized", "Detection Risk", "detection",
]


@dataclass
class Rule:
    target: str                       # relative path (may be a glob under agents/)
    all_of: tuple = ()                # every substring must be present
    any_of_groups: tuple = ()         # each inner list: at least one member present
    when_contains: Optional[str] = None  # apply rule ONLY to files containing this marker


# CLAUDE.md carries the doctrine; every agent must state a guardrail; every agent that can be
# dispatched to TOUCH a target (carries the forked-discipline block) must also state its scope rule.
# The two blind, artifact-only judges (finding-checker/validator) never touch a target, so the
# scope rule is keyed on the "you run forked" marker rather than forced on every agent.
RULES: list[Rule] = [
    Rule("CLAUDE.md",
         all_of=("[CONFIRMED]", "scope_guard.py", "finding-evidence-standards.md", "authorized")),
    Rule("agents/*.md", any_of_groups=(_GUARDRAIL,)),
    Rule("agents/*.md", any_of_groups=(_SCOPE,), when_contains="you run forked"),
]


@dataclass
class Violation:
    file: str
    rule: str          # human-readable description of what was missing

    def to_dict(self) -> dict:
        return {"file": self.file, "rule": self.rule}


def _expand(root: Path, target: str) -> list[Path]:
    if "*" in target:
        base = target.split("/", 1)[0]
        pattern = target.split("/", 1)[1]
        return sorted((root / base).glob(pattern))
    return [root / target]


def check(root: Optional[Path] = None, rules: Optional[list[Rule]] = None) -> list[Violation]:
    root = Path(root) if root else _ROOT
    rules = rules if rules is not None else RULES
    violations: list[Violation] = []
    for rule in rules:
        files = _expand(root, rule.target)
        if not files:
            violations.append(Violation(rule.target, "no files matched (expected at least one)"))
            continue
        for f in files:
            try:
                content = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                violations.append(Violation(str(f.relative_to(root)), "unreadable"))
                continue
            rel = f.relative_to(root).as_posix()
            if rule.when_contains is not None and rule.when_contains not in content:
                continue  # rule not applicable to this file
            for needle in rule.all_of:
                if needle not in content:
                    violations.append(Violation(rel, f"missing required substring {needle!r}"))
            for group in rule.any_of_groups:
                if not any(member in content for member in group):
                    violations.append(Violation(rel, f"missing all of guardrail group {group[:3]}... (need >=1)"))
    return violations


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Assert agents/CLAUDE state their guardrails.")
    p.add_argument("--json", action="store_true")
    p.add_argument("--root")
    args = p.parse_args(argv)
    try:
        violations = check(Path(args.root) if args.root else None)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps([v.to_dict() for v in violations], indent=2))
    else:
        if not violations:
            print("ok: all agents + CLAUDE.md carry their required guardrails")
        else:
            for v in violations:
                print(f"VIOLATION {v.file}: {v.rule}")
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
