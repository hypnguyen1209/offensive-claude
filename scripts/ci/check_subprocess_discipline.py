#!/usr/bin/env python3
"""check_subprocess_discipline.py - ban shell-injection-prone process spawning across the tree.

The plugin shells out a lot (offensive tools drive nmap, impacket, git, ...), and that is fine when
the argv is a list and shell=False. What is NEVER fine is a shell interpreting a constructed string:
`os.system(...)`, `os.popen(...)`, or `subprocess.*(..., shell=True)` turn any interpolated value
into command injection. This check parses each production `.py` with the AST (so payload STRINGS and
detector REGEXES that merely mention these forms are not matched - only real call sites are) and
fails if any appears without an explicit reviewed pragma.

Deliberately NARROW and TRUE: it does not claim "every subprocess goes through safe_subprocess" (many
calls legitimately run trusted local tools) nor "every network call goes through action_guard"
(action_guard is a *runtime* gate, not statically provable). It enforces the one static invariant
that has no legitimate exception-by-default: no shell string execution.

Reviewed exceptions carry an inline pragma on the call's first line:
    subprocess.run(cmd, shell=True, ...)   # noqa: subprocess-discipline - <reason>
The reason is mandatory; a bare pragma is itself a violation (forces a justification into the diff).

CLI:
  check_subprocess_discipline.py            # exit 1 on any unpragma'd violation, 0 clean, 2 error
  check_subprocess_discipline.py --json
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

_ROOT = Path(__file__).resolve().parents[2]
_SCAN_DIRS = ("skills", "engine", "scripts", "hooks")
_SKIP_PARTS = {"__pycache__", ".git", ".pytest_cache", "tests"}
_PRAGMA = "noqa: subprocess-discipline"
_SUBPROCESS_FUNCS = {"run", "Popen", "call", "check_call", "check_output"}


@dataclass
class Violation:
    file: str
    line: int
    kind: str          # "os.system" | "os.popen" | "shell=True" | "bare-pragma"

    def to_dict(self) -> dict:
        return {"file": self.file, "line": self.line, "kind": self.kind}


def _has_shell_true(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


@dataclass
class _Binds:
    """Import bindings resolved per-module so aliasing can't evade the check."""
    sub_modules: set        # names that refer to the `subprocess` module (incl. aliases)
    os_modules: set         # names that refer to the `os` module (incl. aliases)
    sub_funcs: dict         # bare name -> subprocess func (from `from subprocess import run [as r]`)
    os_banned: dict         # bare name -> "os.system"/"os.popen" (from `from os import system [as s]`)


def _collect_binds(tree: ast.AST) -> _Binds:
    sub_modules, os_modules, sub_funcs, os_banned = set(), set(), {}, {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "subprocess":
                    sub_modules.add(alias.asname or "subprocess")
                elif alias.name == "os":
                    os_modules.add(alias.asname or "os")
        elif isinstance(node, ast.ImportFrom):
            if node.module == "subprocess":
                for alias in node.names:
                    if alias.name in _SUBPROCESS_FUNCS:
                        sub_funcs[alias.asname or alias.name] = alias.name
            elif node.module == "os":
                for alias in node.names:
                    if alias.name in ("system", "popen"):
                        os_banned[alias.asname or alias.name] = f"os.{alias.name}"
    return _Binds(sub_modules, os_modules, sub_funcs, os_banned)


def _scan_source(text: str) -> list[tuple[int, str]]:
    """Return (lineno, kind) for each banned call site. AST-based: strings/comments never match.

    Resolves import aliases so `import subprocess as sp; sp.run(shell=True)` and
    `from os import system as s; s(...)` are caught, not just the canonical dotted forms."""
    hits: list[tuple[int, str]] = []
    tree = ast.parse(text)
    b = _collect_binds(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        # attribute form:  <mod>.<attr>(...)
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            mod, attr = func.value.id, func.attr
            if mod in b.os_modules and attr in ("system", "popen"):
                hits.append((node.lineno, f"os.{attr}"))
            elif mod in b.sub_modules and attr in _SUBPROCESS_FUNCS and _has_shell_true(node):
                hits.append((node.lineno, "shell=True"))
        # bare-name form from a `from ... import`:  system(...) / run(shell=True)
        elif isinstance(func, ast.Name):
            if func.id in b.os_banned:
                hits.append((node.lineno, b.os_banned[func.id]))
            elif func.id in b.sub_funcs and _has_shell_true(node):
                hits.append((node.lineno, "shell=True"))
    return hits


def check(root: Optional[Path] = None) -> list[Violation]:
    root = Path(root) if root else _ROOT
    violations: list[Violation] = []
    for d in _SCAN_DIRS:
        base = root / d
        if not base.exists():
            continue
        for p in sorted(base.rglob("*.py")):
            if any(part in _SKIP_PARTS for part in p.relative_to(root).parts):
                continue
            try:
                text = p.read_text(encoding="utf-8")
                hits = _scan_source(text)
            except (OSError, SyntaxError) as exc:
                violations.append(Violation(p.relative_to(root).as_posix(), 0, f"unparseable: {exc.__class__.__name__}"))
                continue
            if not hits:
                continue
            lines = text.splitlines()
            rel = p.relative_to(root).as_posix()
            for lineno, kind in hits:
                src = lines[lineno - 1] if 0 < lineno <= len(lines) else ""
                if _PRAGMA in src:
                    # pragma present - require a non-empty reason after a '-'
                    after = src.split(_PRAGMA, 1)[1].lstrip()
                    if after.startswith("-") and after[1:].strip():
                        continue  # justified, reviewed exception
                    violations.append(Violation(rel, lineno, "bare-pragma"))
                else:
                    violations.append(Violation(rel, lineno, kind))
    return violations


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Ban os.system/os.popen/shell=True (shell injection) in the tree.")
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
            print("ok: no shell-injection-prone process spawning (os.system/os.popen/shell=True)")
        else:
            for v in violations:
                print(f"VIOLATION {v.file}:{v.line} [{v.kind}]")
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
