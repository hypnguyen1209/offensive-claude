#!/usr/bin/env python3
"""build_graph.py - a scoped source-to-sink code graph in stdlib sqlite (codegraph + graphify model).

Candidate GENERATION for the audit pipeline - never proof. It builds a nodes/edges graph the
traversal tools (`traverse.py`, `affected.py`, `attack_surface.py`) walk to orient source-to-sink
hunting, and every edge carries a PROVENANCE that feeds PR-3's per-hop gate
(`skills/vulnerability-analysis/scripts/provenance.py`):

  EXTRACTED - a literal call resolved unambiguously to a def IN THE SAME FILE.
  INFERRED  - name-bridged: a bare/attribute call resolved by short name to exactly one def elsewhere
              (receiver type / import not resolved - a lead, not a fact).
  AMBIGUOUS - the callee name matched MORE THAN ONE def (over-approximated: an edge to each candidate).
  (unresolved - zero matches - is recorded in `unresolved_refs` for a later retry, NOT as an edge.)

A path is only as strong as its weakest hop, so a source-to-sink chain with any INFERRED/AMBIGUOUS
edge cannot ground a [CONFIRMED] finding - exactly the cap PR-3 enforces.

Extractor: Python `ast` (precise, stdlib) for `.py`. Other languages need the optional tree-sitter
path (documented, not bundled) - build_graph indexes only what it can parse precisely and says so.

Design choices (graphify/codegraph):
  * Content-addressed node id = sha256(kind\\0file\\0qualified_name)[:16] - stable across re-scans so an
    [EVD-XXX] anchor survives an edit that only moves a symbol's line. (Two same-kind same-qname defs
    in one file collide - rare; the later def's edges merge. Noted, not silently precise.)
  * Two-phase extract -> resolve. Extraction is per-file and CACHED by content hash (incremental
    reindex skips unchanged files); resolution always re-runs globally over the full symbol set (cheap,
    in-memory) so a new symbol can satisfy a ref from an unchanged file.
  * UNIQUE(source,target,kind,line,col) edge dedup.
  * Shrink-guard: refuse to overwrite a larger existing graph with a smaller one (a truncated/aborted
    parse must not silently shrink a good graph) unless --allow-shrink.
  * Scope: extraction is confined to --root; symlinks pointing outside root are refused (path-escape
    guard). Host/asset scope (scope_guard.py) is orthogonal - a local checkout is the authorized unit.

CLI:
  build_graph.py <root> --db graph.sqlite [--incremental] [--allow-shrink] [--json]
  build_graph.py <root> --db graph.sqlite --stats
Exit: 0 ok (incl. recoverable "nothing to index" with guidance), 2 error, 3 shrink-guard refusal.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import sqlite3
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

SCHEMA_VERSION = 1
_PARSEABLE = {".py"}
_SKIP_DIRS = {"node_modules", ".git", "vendor", "venv", ".venv", "dist", "build",
              "__pycache__", "target", ".mypy_cache", ".pytest_cache", ".tox", "site-packages"}
# generated/vendored markers -> symbols get generated=1 and rank below hand-written code (codegraph).
_GENERATED_MARKERS = ("_pb2.py", ".min.js", "generated", "/migrations/", "\\migrations\\")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS files (
    path TEXT PRIMARY KEY, sha256 TEXT NOT NULL, generated INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS symbols (
    id TEXT PRIMARY KEY, kind TEXT NOT NULL, name TEXT NOT NULL, qualified_name TEXT NOT NULL,
    file TEXT NOT NULL, line INTEGER, end_line INTEGER, signature TEXT, generated INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS callsites (
    id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL, callee_name TEXT NOT NULL,
    callee_kind TEXT NOT NULL, file TEXT NOT NULL, line INTEGER, col INTEGER);
CREATE TABLE IF NOT EXISTS edges (
    id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL, target TEXT NOT NULL, kind TEXT NOT NULL,
    file TEXT, line INTEGER, col INTEGER, provenance TEXT NOT NULL, metadata TEXT,
    UNIQUE(source, target, kind, line, col));
CREATE TABLE IF NOT EXISTS unresolved_refs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL, ref_name TEXT NOT NULL,
    callee_kind TEXT, file TEXT, line INTEGER, col INTEGER);
CREATE INDEX IF NOT EXISTS ix_symbols_name ON symbols(name);
CREATE INDEX IF NOT EXISTS ix_symbols_file ON symbols(file);
CREATE INDEX IF NOT EXISTS ix_edges_source ON edges(source);
CREATE INDEX IF NOT EXISTS ix_edges_target ON edges(target);
CREATE INDEX IF NOT EXISTS ix_callsites_source ON callsites(source);
"""

EXTRACTED, INFERRED, AMBIGUOUS = "EXTRACTED", "INFERRED", "AMBIGUOUS"


def node_id(kind: str, file: str, qualified_name: str) -> str:
    """Stable content-addressed id (line-independent, so anchors survive line-moving edits)."""
    blob = f"{kind}\0{file}\0{qualified_name}".encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:16]


def _is_generated(rel: str) -> bool:
    r = rel.replace("\\", "/").lower()
    return any(m.replace("\\", "/") in r for m in _GENERATED_MARKERS)


@dataclass
class Symbol:
    id: str
    kind: str
    name: str
    qualified_name: str
    file: str
    line: int
    end_line: int
    signature: str
    generated: int = 0


@dataclass
class Callsite:
    source: str
    callee_name: str
    callee_kind: str      # "name" (bare f()) | "attr" (obj.method())
    file: str
    line: int
    col: int


@dataclass
class FileExtract:
    symbols: list = field(default_factory=list)
    callsites: list = field(default_factory=list)


# --------------------------------------------------------------- Python ast extractor
class _PyVisitor(ast.NodeVisitor):
    def __init__(self, rel: str, generated: int, module_id: str):
        self.rel = rel
        self.generated = generated
        self.scope: list = []          # qualified-name stack
        self.kind_stack: list = []     # parallel stack of scope kinds ("class"/"function")
        self.symbols: list = []
        self.callsites: list = []
        self._sym_stack: list = [module_id]   # enclosing symbol id (for callsite.source)

    def _qual(self, name: str) -> str:
        return ".".join(self.scope + [name]) if self.scope else name

    def _signature(self, node) -> str:
        try:
            args = [a.arg for a in node.args.args]
            if getattr(node.args, "vararg", None):
                args.append("*" + node.args.vararg.arg)
            if getattr(node.args, "kwarg", None):
                args.append("**" + node.args.kwarg.arg)
            return f"{node.name}({', '.join(args)})"
        except AttributeError:
            return getattr(node, "name", "")

    def _add_def(self, node, kind: str, scope_kind: str):
        qn = self._qual(node.name)
        sid = node_id(kind, self.rel, qn)
        sig = f"class {node.name}" if kind == "class" else self._signature(node)
        self.symbols.append(Symbol(sid, kind, node.name, qn, self.rel,
                                   getattr(node, "lineno", 0),
                                   getattr(node, "end_lineno", getattr(node, "lineno", 0)),
                                   sig, self.generated))
        self.scope.append(node.name)
        self.kind_stack.append(scope_kind)
        self._sym_stack.append(sid)
        self.generic_visit(node)
        self._sym_stack.pop()
        self.kind_stack.pop()
        self.scope.pop()

    def visit_FunctionDef(self, node):
        # a def whose IMMEDIATE enclosing scope is a class is a method; otherwise a function
        kind = "method" if (self.kind_stack and self.kind_stack[-1] == "class") else "function"
        self._add_def(node, kind, "function")

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self._add_def(node, "class", "class")

    def visit_Call(self, node):
        src = self._sym_stack[-1]
        f = node.func
        if isinstance(f, ast.Name):
            self.callsites.append(Callsite(src, f.id, "name", self.rel,
                                           getattr(node, "lineno", 0), getattr(node, "col_offset", 0)))
        elif isinstance(f, ast.Attribute):
            self.callsites.append(Callsite(src, f.attr, "attr", self.rel,
                                           getattr(node, "lineno", 0), getattr(node, "col_offset", 0)))
        self.generic_visit(node)


def extract_python(rel: str, text: str, generated: int) -> FileExtract:
    """Precise per-file extraction via ast. A syntax error yields an EMPTY extract (the file simply
    isn't indexed) rather than aborting the whole build."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return FileExtract([], [])
    # a synthetic module node so top-level callsites have a source symbol
    mod_id = node_id("module", rel, "<module>")
    v = _PyVisitor(rel, generated, mod_id)
    v.visit(tree)
    syms = [Symbol(mod_id, "module", "<module>", "<module>", rel, 1,
                   text.count("\n") + 1, rel, generated)] + v.symbols
    return FileExtract(syms, v.callsites)


def _iter_source_files(root: Path):
    """Yield (abspath, relposix) for parseable files under root, refusing symlink escapes."""
    root = root.resolve()
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS and not os.path.islink(os.path.join(dp, d))]
        for f in fn:
            ext = os.path.splitext(f)[1].lower()
            if ext not in _PARSEABLE:
                continue
            ap = os.path.join(dp, f)
            if os.path.islink(ap):
                # refuse a symlink that resolves outside root (path-escape guard)
                try:
                    if not Path(os.path.realpath(ap)).resolve().is_relative_to(root):
                        continue
                except (OSError, ValueError):
                    continue
            yield ap, Path(ap).resolve().relative_to(root).as_posix()


# --------------------------------------------------------------- db plumbing
def _connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.executescript(_SCHEMA)
    conn.commit()
    return conn


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def _get_meta(conn, key, default=None):
    row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row[0] if row else default


# --------------------------------------------------------------- resolve phase
def _resolve(conn) -> dict:
    """Rebuild the edges table from callsites + symbols. Returns counts by provenance."""
    conn.execute("DELETE FROM edges")
    conn.execute("DELETE FROM unresolved_refs")
    # containment edges: every symbol -> its lexical children by qualified-name prefix (module owns
    # top-level defs; a class owns its methods). Cheap: parent qname is child qname minus last part.
    by_qname_file: dict = {}
    name_index: dict = {}
    for sid, kind, name, qn, fpath in conn.execute(
            "SELECT id, kind, name, qualified_name, file FROM symbols"):
        by_qname_file[(fpath, qn)] = sid
        name_index.setdefault(name, []).append((sid, fpath, kind))
    # contains edges
    for (fpath, qn), sid in by_qname_file.items():
        if "." in qn:
            parent_qn = qn.rsplit(".", 1)[0]
            pid = by_qname_file.get((fpath, parent_qn))
            if pid:
                conn.execute("INSERT OR IGNORE INTO edges (source,target,kind,file,line,col,provenance,metadata)"
                             " VALUES (?,?,?,?,?,?,?,?)",
                             (pid, sid, "contains", fpath, None, None, EXTRACTED, None))
        elif qn != "<module>":
            mid = by_qname_file.get((fpath, "<module>"))
            if mid:
                conn.execute("INSERT OR IGNORE INTO edges (source,target,kind,file,line,col,provenance,metadata)"
                             " VALUES (?,?,?,?,?,?,?,?)",
                             (mid, sid, "contains", fpath, None, None, EXTRACTED, None))
    counts = {EXTRACTED: 0, INFERRED: 0, AMBIGUOUS: 0, "unresolved": 0}
    for cid, src, callee, ckind, fpath, line, col in conn.execute(
            "SELECT id, source, callee_name, callee_kind, file, line, col FROM callsites"):
        cands = name_index.get(callee, [])
        callable_cands = [(sid, cf, k) for sid, cf, k in cands if k in ("function", "method", "class")]
        if not callable_cands:
            conn.execute("INSERT INTO unresolved_refs (source,ref_name,callee_kind,file,line,col)"
                         " VALUES (?,?,?,?,?,?)", (src, callee, ckind, fpath, line, col))
            counts["unresolved"] += 1
            continue
        if len(callable_cands) == 1:
            tid, tf, _k = callable_cands[0]
            prov = EXTRACTED if (ckind == "name" and tf == fpath) else INFERRED
            _add_call_edge(conn, src, tid, fpath, line, col, prov)
            counts[prov] += 1
        else:
            # over-approximate: an AMBIGUOUS edge to every candidate (weakest provenance)
            for tid, _tf, _k in callable_cands:
                _add_call_edge(conn, src, tid, fpath, line, col, AMBIGUOUS)
            counts[AMBIGUOUS] += 1
    conn.commit()
    return counts


def _add_call_edge(conn, src, tid, fpath, line, col, prov):
    conn.execute("INSERT OR IGNORE INTO edges (source,target,kind,file,line,col,provenance,metadata)"
                 " VALUES (?,?,?,?,?,?,?,?)", (src, tid, "calls", fpath, line, col, prov, None))


# --------------------------------------------------------------- build
@dataclass
class BuildResult:
    root: str
    files_indexed: int
    files_skipped_unchanged: int
    symbols: int
    edges: int
    provenance: dict
    shrunk_refused: bool = False

    def to_dict(self) -> dict:
        return {"root": self.root, "files_indexed": self.files_indexed,
                "files_skipped_unchanged": self.files_skipped_unchanged, "symbols": self.symbols,
                "edges": self.edges, "provenance": self.provenance, "shrunk_refused": self.shrunk_refused}


def build(root: str, db_path: str, *, incremental: bool = False,
          allow_shrink: bool = False) -> BuildResult:
    root_path = Path(root)
    if not root_path.is_dir():
        raise NotADirectoryError(f"root is not a directory: {root}")
    conn = _connect(db_path)
    try:
        prior_symbols = int(_get_meta(conn, "node_count", "0") or 0)
        seen_files = set()
        indexed = skipped = 0
        for ap, rel in _iter_source_files(root_path):
            seen_files.add(rel)
            try:
                text = Path(ap).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            digest = _sha256(text)
            generated = 1 if _is_generated(rel) else 0
            if incremental:
                row = conn.execute("SELECT sha256 FROM files WHERE path=?", (rel,)).fetchone()
                if row and row[0] == digest:
                    skipped += 1
                    continue
            # (re)extract this file: purge its old rows first
            conn.execute("DELETE FROM symbols WHERE file=?", (rel,))
            conn.execute("DELETE FROM callsites WHERE file=?", (rel,))
            ex = extract_python(rel, text, generated)
            for s in ex.symbols:
                conn.execute("INSERT OR REPLACE INTO symbols "
                             "(id,kind,name,qualified_name,file,line,end_line,signature,generated)"
                             " VALUES (?,?,?,?,?,?,?,?,?)",
                             (s.id, s.kind, s.name, s.qualified_name, s.file, s.line, s.end_line,
                              s.signature, s.generated))
            for c in ex.callsites:
                conn.execute("INSERT INTO callsites (source,callee_name,callee_kind,file,line,col)"
                             " VALUES (?,?,?,?,?,?)",
                             (c.source, c.callee_name, c.callee_kind, c.file, c.line, c.col))
            conn.execute("INSERT OR REPLACE INTO files (path,sha256,generated) VALUES (?,?,?)",
                         (rel, digest, generated))
            indexed += 1
        # drop files (and their symbols) that vanished from the tree
        if incremental:
            for (gone,) in conn.execute("SELECT path FROM files").fetchall():
                if gone not in seen_files:
                    conn.execute("DELETE FROM symbols WHERE file=?", (gone,))
                    conn.execute("DELETE FROM callsites WHERE file=?", (gone,))
                    conn.execute("DELETE FROM files WHERE path=?", (gone,))
        prov = _resolve(conn)
        n_syms = conn.execute("SELECT COUNT(*) FROM symbols").fetchone()[0]
        n_edges = conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
        # shrink-guard: refuse to persist a smaller graph over a larger prior one
        if prior_symbols and n_syms < prior_symbols and not allow_shrink and not incremental:
            conn.rollback()
            return BuildResult(str(root), 0, 0, prior_symbols, 0, {}, shrunk_refused=True)
        conn.execute("INSERT OR REPLACE INTO meta (key,value) VALUES ('schema_version',?)",
                     (str(SCHEMA_VERSION),))
        conn.execute("INSERT OR REPLACE INTO meta (key,value) VALUES ('root',?)", (str(root),))
        conn.execute("INSERT OR REPLACE INTO meta (key,value) VALUES ('node_count',?)", (str(n_syms),))
        conn.commit()
        return BuildResult(str(root), indexed, skipped, n_syms, n_edges, prov)
    finally:
        conn.close()


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(description="Build a scoped source-to-sink code graph (sqlite).")
    p.add_argument("root")
    p.add_argument("--db", required=True)
    p.add_argument("--incremental", action="store_true", help="reuse unchanged files (content-hash)")
    p.add_argument("--allow-shrink", action="store_true", help="permit overwriting with a smaller graph")
    p.add_argument("--stats", action="store_true", help="print stats for an existing graph and exit")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    if args.stats:
        try:
            conn = _connect(args.db)
            n = conn.execute("SELECT COUNT(*) FROM symbols").fetchone()[0]
            e = conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
            u = conn.execute("SELECT COUNT(*) FROM unresolved_refs").fetchone()[0]
            conn.close()
        except sqlite3.Error as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(json.dumps({"symbols": n, "edges": e, "unresolved_refs": u}, indent=2)
              if args.json else f"symbols={n} edges={e} unresolved_refs={u}")
        return 0

    try:
        res = build(args.root, args.db, incremental=args.incremental, allow_shrink=args.allow_shrink)
    except (OSError, sqlite3.Error, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if res.shrunk_refused:
        print(f"refused: new graph ({res.symbols} prior symbols) would shrink - pass --allow-shrink "
              "if the smaller graph is intended", file=sys.stderr)
        return 3
    if args.json:
        print(json.dumps(res.to_dict(), indent=2))
    elif res.symbols == 0:
        # recoverable, not an error: guide the operator (errors teach abandonment)
        print(f"indexed 0 symbols under {args.root} - is it a Python source tree? "
              "(only .py is precisely parsed; other languages need the optional tree-sitter path)")
    else:
        print(f"indexed {res.files_indexed} file(s) ({res.files_skipped_unchanged} unchanged), "
              f"{res.symbols} symbols, {res.edges} edges; provenance={res.provenance}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
