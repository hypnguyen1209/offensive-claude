#!/usr/bin/env python3
"""pack_target.py - pack a scoped local checkout into one bounded, structure-first audit brief (repomix).

Flattens a target repo into a single `.engage/recon/target-pack.md` for an audit agent: a directory
tree first (cheap structure), then file bodies until a token budget is spent. Three properties matter
for an OFFENSIVE, authorized engagement:

  * secret gate is ON and fail-closed (PR-1). Every file body is scanned with secret_scan.py BEFORE it
    enters the pack; any credential line is replaced in place with a value-free marker
    (`[REDACTED secret: <rule> @ line N]`). A target's live secrets never reach model context or a
    report (CWE-532) - only the rule + location survive.
  * bounded + token-counted, NO silent truncation. Files are added in a deterministic order until the
    `--max-tokens` budget is hit; everything skipped is LISTED (graphify/repomix: a bound the reader
    can't see reads as "covered everything" when it wasn't). Token count is a stdlib chars/4 estimate
    (no tiktoken dependency) - documented as an estimate, not a promise.
  * signature-only `--compress` mode for large targets: Python files are reduced to their def/class
    signatures via `ast` (degrade-to-FULL-body on SyntaxError, and non-Python files stay full - we
    ship no tree-sitter, so this is honest about what it can and cannot skeletonize).

Confined to `--root` with a symlink-escape guard (a symlink pointing outside the checkout is skipped),
same as build_graph.py. Host/engagement scope (scope_guard) is orthogonal to a local checkout.

CLI:
  pack_target.py --root ./target [--out .engage/recon/target-pack.md] [--max-tokens 50000]
                 [--compress] [--lang py,js,go] [--json]
Exit: 0 (incl. a fully-dropped budget with guidance), 2 on a genuine error.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# secret_scan lives under skills/coding-mastery/scripts/_lib
_LIB = Path(__file__).resolve().parents[2] / "skills" / "coding-mastery" / "scripts" / "_lib"
sys.path.insert(0, str(_LIB))
import secret_scan as ss  # noqa: E402

_SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
              ".mypy_cache", ".pytest_cache", "dist", "build", ".tox", ".idea", ".engage"}
# text-like source/config extensions worth packing for an audit
_TEXT_EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".rb", ".php", ".java", ".c",
              ".h", ".cpp", ".cc", ".hpp", ".cs", ".sh", ".ps1", ".sql", ".yaml", ".yml",
              ".toml", ".ini", ".cfg", ".json", ".env", ".conf", ".md", ".txt", ".xml", ".html"}
_MAX_FILE_BYTES = 1_000_000   # skip anything bigger (minified bundles, blobs) - reported as dropped


def estimate_tokens(text: str) -> int:
    """Cheap stdlib token estimate (~4 chars/token). An ESTIMATE, not tiktoken - documented as such."""
    return (len(text) + 3) // 4


def _py_signatures(text: str) -> Optional[str]:
    """Python def/class signatures only, in source order. None on SyntaxError (caller degrades to full)."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return None
    rows: list[tuple[int, int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            bases = ", ".join(ast.unparse(b) for b in node.bases)
            sig = f"class {node.name}({bases}):" if bases else f"class {node.name}:"
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            kw = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
            sig = f"{kw} {node.name}({ast.unparse(node.args)}):"
        else:
            continue
        rows.append((node.lineno, node.col_offset, " " * node.col_offset + sig + " ..."))
    rows.sort(key=lambda r: (r[0], r[1]))
    return "\n".join(r[2] for r in rows) if rows else "# (no definitions)"


def _redact(text: str) -> tuple[str, list[dict]]:
    """Replace any secret-bearing LINE with a value-free marker. Returns (safe_text, hit_dicts)."""
    hits = ss.scan(text)
    if not hits:
        return text, []
    by_line: dict[int, list[str]] = {}
    for h in hits:
        by_line.setdefault(h.line, []).append(h.rule)
    lines = text.splitlines()
    for ln, rules in by_line.items():
        if 1 <= ln <= len(lines):
            uniq = ", ".join(sorted(set(rules)))
            lines[ln - 1] = f"[REDACTED secret: {uniq} @ line {ln}]"
    return "\n".join(lines), [h.to_dict() for h in hits]


@dataclass
class PackedFile:
    path: str
    tokens: int
    mode: str            # "full" | "signatures" | "skipped-budget" | "skipped-size" | "skipped-binary"
    secrets: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"path": self.path, "tokens": self.tokens, "mode": self.mode, "secrets": self.secrets}


@dataclass
class PackResult:
    root: str
    total_tokens: int
    included: list = field(default_factory=list)
    dropped: list = field(default_factory=list)
    secret_files: int = 0
    body: str = ""

    def to_dict(self) -> dict:
        return {"root": self.root, "total_tokens": self.total_tokens,
                "included": [f.to_dict() for f in self.included],
                "dropped": [f.to_dict() for f in self.dropped],
                "secret_files": self.secret_files}


def _safe_files(root: Path) -> list:
    """Deterministic, symlink-escape-guarded list of candidate files (sorted, root-relative)."""
    root = root.resolve()
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
        for fn in sorted(filenames):
            fp = Path(dirpath) / fn
            try:
                rp = fp.resolve()
                if not rp.is_relative_to(root):   # symlink escaping the checkout
                    continue
            except (OSError, ValueError):
                continue
            out.append(fp)
    return out


def _read(fp: Path) -> Optional[str]:
    try:
        if fp.stat().st_size > _MAX_FILE_BYTES:
            return None
        return fp.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _tree(root: Path, files: list) -> str:
    rels = sorted(str(f.resolve().relative_to(root.resolve())).replace("\\", "/") for f in files)
    return "\n".join(rels)


def pack(root: str, *, max_tokens: int = 50_000, compress: bool = False,
         langs: Optional[set] = None) -> PackResult:
    root_p = Path(root)
    files = _safe_files(root_p)
    if langs:
        want = {("." + l.lstrip(".")).lower() for l in langs}
        files = [f for f in files if f.suffix.lower() in want]
    else:
        files = [f for f in files if f.suffix.lower() in _TEXT_EXTS]

    tree = _tree(root_p, files)
    header = f"# Target pack: {root_p.as_posix()}\n\n## Structure\n\n```\n{tree}\n```\n\n## Files\n"
    budget = max(1, max_tokens)
    used = estimate_tokens(header)
    result = PackResult(root=root_p.as_posix(), total_tokens=0)
    chunks = [header]

    for fp in files:
        rel = str(fp.resolve().relative_to(root_p.resolve())).replace("\\", "/")
        raw = _read(fp)
        if raw is None:
            result.dropped.append(PackedFile(rel, 0, "skipped-size"))
            continue
        if "\x00" in raw[:4096]:
            result.dropped.append(PackedFile(rel, 0, "skipped-binary"))
            continue
        safe, hits = _redact(raw)               # secret gate ON, before anything is emitted
        if hits:
            result.secret_files += 1
        mode = "full"
        content = safe
        if compress and fp.suffix.lower() == ".py":
            sigs = _py_signatures(safe)          # sign the already-redacted text
            if sigs is not None:
                content, mode = sigs, "signatures"
        block = f"\n### {rel}\n\n```\n{content}\n```\n"
        cost = estimate_tokens(block)
        if used + cost > budget:
            result.dropped.append(PackedFile(rel, cost, "skipped-budget", hits))
            continue
        used += cost
        chunks.append(block)
        result.included.append(PackedFile(rel, cost, mode, hits))

    result.body = "".join(chunks)
    result.total_tokens = used
    return result


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(description="Pack a scoped checkout into a bounded audit brief.")
    p.add_argument("--root", required=True)
    p.add_argument("--out", default=".engage/recon/target-pack.md")
    p.add_argument("--max-tokens", type=int, default=50_000)
    p.add_argument("--compress", action="store_true", help="Python def/class signatures only")
    p.add_argument("--lang", help="comma-separated extensions to include (e.g. py,js,go)")
    p.add_argument("--json", action="store_true", help="print the manifest as JSON, do not write --out")
    args = p.parse_args(argv)

    root = Path(args.root)
    if not root.is_dir():
        print(f"error: --root {args.root!r} is not a directory", file=sys.stderr)
        return 2
    langs = {x.strip() for x in args.lang.split(",")} if args.lang else None
    try:
        res = pack(str(root), max_tokens=max(1, args.max_tokens), compress=args.compress, langs=langs)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(res.to_dict(), indent=2))
    else:
        out = Path(args.out)
        try:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(res.body, encoding="utf-8")
        except OSError as exc:
            print(f"error: cannot write {args.out}: {exc}", file=sys.stderr)
            return 2
        print(f"packed {len(res.included)} file(s), ~{res.total_tokens} tokens -> {args.out}")
        if res.secret_files:
            print(f"secret gate: redacted secret-bearing lines in {res.secret_files} file(s) "
                  "(values masked; only rule + line kept)")
        if res.dropped:
            budget_dropped = [d for d in res.dropped if d.mode == "skipped-budget"]
            if budget_dropped:
                print(f"NOT PACKED - token budget ({args.max_tokens}) reached, "
                      f"{len(budget_dropped)} file(s) dropped (raise --max-tokens or use --compress):")
                for d in budget_dropped[:20]:
                    print(f"  {d.path}")
            other = [d for d in res.dropped if d.mode != "skipped-budget"]
            if other:
                print(f"skipped {len(other)} non-text/oversize file(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
