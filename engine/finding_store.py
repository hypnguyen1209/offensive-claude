#!/usr/bin/env python3
"""finding_store.py - a scoped FTS5 finding store with 3-layer retrieval (claude-mem).

Replaces "inject every prior finding into context" (which bloats a long engagement) with a
retrieve-what-you-need store. Three layers, cheapest first:

  1. search(query)     -> a COMPACT index (fid / cwe / severity / title / status). Small rows you scan.
  2. timeline(anchor)  -> the findings temporally around one anchor (same-phase neighbourhood).
  3. get(fids)         -> FULL bodies, and ONLY for the ids you chose after layers 1-2.

Backed by sqlite3 + FTS5 (`porter unicode61`, in stock CPython - no new dep), a trigger-synced
external-content mirror, and:

  * scope isolation (project-guard). The store is BOUND to one engagement scope at init; a finding
    whose scope differs is rejected - in Python AND by a `RAISE(ABORT)` trigger (defence in depth), so
    one engagement's findings can never bleed into another's store.
  * count-mismatch auto-rebuild. On open, if COUNT(findings) != COUNT(fts) the FTS index is rebuilt -
    a desynced mirror self-heals instead of silently returning wrong hits.
  * write-boundary redaction. Every title/body is run through private_tag (operator `<private>` spans)
    then secret_scan (credential shapes) BEFORE it is stored - loot and marked-private content never
    persist (CWE-532).
  * token economics. recall_cost / rediscovery_estimate / plan_recall enforce a recall budget with NO
    silent truncation (over-budget ids are listed, not dropped in silence). telemetry() is counts/enums
    only - never content.

CLI:
  finding_store.py init   --db f.db --scope acme-prod
  finding_store.py add    --db f.db --json '<finding json>'    (or - for stdin)
  finding_store.py search --db f.db --query "ssrf metadata" [--limit 25]
  finding_store.py timeline --db f.db --anchor <fid> [--window 5]
  finding_store.py get    --db f.db --ids a,b,c [--budget 4000]
  finding_store.py telemetry --db f.db
  finding_store.py verify --db f.db          # integrity check + FTS rebuild if desynced
Exit: 0 ok, 2 error, 3 scope violation (so automation can branch).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
import time
from typing import Optional

_LIB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                    "skills", "coding-mastery", "scripts", "_lib")
sys.path.insert(0, os.path.abspath(_LIB))
import private_tag  # noqa: E402
import secret_scan  # noqa: E402

SCHEMA_VERSION = 1
SEVERITY_RANK = {"info": 0, "informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
# re-deriving a finding costs far more than re-reading its distilled record; a conservative,
# clearly-labelled multiplier (NOT a measurement) for the "why keep memory" economics.
REDISCOVER_FACTOR = 8


class ScopeError(Exception):
    """A finding's scope does not match the store's bound engagement scope."""


class StoreError(Exception):
    """A malformed finding or store error."""


# --------------------------------------------------------------------------- schema
def _fts5_available() -> bool:
    try:
        c = sqlite3.connect(":memory:")
        c.execute("CREATE VIRTUAL TABLE _p USING fts5(a)")
        c.close()
        return True
    except sqlite3.OperationalError:
        return False


_HAS_FTS5 = _fts5_available()

_BASE_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS findings (
  rowid      INTEGER PRIMARY KEY,
  fid        TEXT UNIQUE NOT NULL,
  cwe        TEXT NOT NULL DEFAULT '',
  severity   TEXT NOT NULL DEFAULT 'info',
  title      TEXT NOT NULL DEFAULT '',
  phase      TEXT NOT NULL DEFAULT '',
  scope      TEXT NOT NULL DEFAULT '',
  status     TEXT NOT NULL DEFAULT 'possible',
  confidence REAL,
  body       TEXT NOT NULL DEFAULT '',
  ts         REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_findings_ts ON findings(ts);
CREATE INDEX IF NOT EXISTS idx_findings_sev ON findings(severity);
-- scope isolation (project-guard): only active once a NON-EMPTY scope is bound.
CREATE TRIGGER IF NOT EXISTS findings_scope_guard BEFORE INSERT ON findings
WHEN (SELECT value FROM meta WHERE key='scope') IS NOT NULL
 AND (SELECT value FROM meta WHERE key='scope') <> ''
 AND NEW.scope <> (SELECT value FROM meta WHERE key='scope')
BEGIN
  SELECT RAISE(ABORT, 'scope violation: finding scope does not match this engagement store');
END;
"""

# A content-OWNING FTS5 mirror (not external-content): COUNT(*) reflects the true index row count,
# so a desynced mirror is detectable by a count mismatch (external-content COUNT reads the base table
# and would hide drift). Triggers keep rowid == findings.rowid so search can JOIN back.
_FTS_SCHEMA = """
CREATE VIRTUAL TABLE IF NOT EXISTS findings_fts USING fts5(title, body, tokenize='porter unicode61');
CREATE TRIGGER IF NOT EXISTS findings_ai AFTER INSERT ON findings BEGIN
  INSERT INTO findings_fts(rowid, title, body) VALUES (new.rowid, new.title, new.body);
END;
CREATE TRIGGER IF NOT EXISTS findings_ad AFTER DELETE ON findings BEGIN
  DELETE FROM findings_fts WHERE rowid = old.rowid;
END;
CREATE TRIGGER IF NOT EXISTS findings_au AFTER UPDATE ON findings BEGIN
  UPDATE findings_fts SET title = new.title, body = new.body WHERE rowid = new.rowid;
END;
"""


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(_BASE_SCHEMA)
    if _HAS_FTS5:
        conn.executescript(_FTS_SCHEMA)
    conn.execute("INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', ?)",
                 (str(SCHEMA_VERSION),))
    conn.commit()


def bound_scope(conn: sqlite3.Connection) -> str:
    row = conn.execute("SELECT value FROM meta WHERE key='scope'").fetchone()
    return row[0] if row and row[0] is not None else ""


def open_store(db_path: str, *, scope: Optional[str] = None, create: bool = True) -> sqlite3.Connection:
    """Open (and optionally create) a store. Binds `scope` on first use; refuses to REBIND a
    store already bound to a different non-empty scope. Auto-rebuilds a desynced FTS mirror."""
    if not create and not os.path.isfile(db_path):
        raise StoreError(f"no store at {db_path} (run `init` first)")
    conn = sqlite3.connect(db_path)
    _ensure_schema(conn)
    if scope is not None:
        cur = bound_scope(conn)
        if cur and scope and cur != scope:
            conn.close()
            raise ScopeError(f"store is bound to scope {cur!r}, refusing to rebind to {scope!r}")
        if scope:
            conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('scope', ?)", (scope,))
            conn.commit()
    verify_integrity(conn, rebuild=True)
    return conn


# --------------------------------------------------------------------------- write boundary
def _redact_secrets(text: str) -> str:
    """Replace any secret-bearing LINE with a value-free marker (only rule + line survive)."""
    hits = secret_scan.scan(text)
    if not hits:
        return text
    by_line: dict = {}
    for h in hits:
        by_line.setdefault(h.line, []).append(h.rule)
    lines = text.splitlines()
    for ln, rules in by_line.items():
        if 1 <= ln <= len(lines):
            lines[ln - 1] = f"[REDACTED secret: {', '.join(sorted(set(rules)))} @ line {ln}]"
    return "\n".join(lines)


def _sanitize(text: Optional[str]) -> str:
    """Boundary redaction applied to everything before it persists: private spans, then secrets."""
    clean, _ = private_tag.strip_private(text or "")
    return _redact_secrets(clean or "")


def derive_fid(scope: str, title: str, cwe: str) -> str:
    """Stable content id: same (scope, title, cwe) -> same fid, so a re-add updates in place."""
    key = "\0".join([(scope or "").strip().lower(), (title or "").strip().lower(),
                     (cwe or "").strip().upper()])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def add_finding(conn: sqlite3.Connection, finding: dict, *, ts: Optional[float] = None) -> str:
    """Insert or update one finding. Returns its fid. Raises ScopeError on a scope mismatch,
    StoreError on a malformed record."""
    if not isinstance(finding, dict):
        raise StoreError("finding must be an object")
    title = _sanitize(str(finding.get("title", "")))
    body = _sanitize(str(finding.get("body", "")))
    # Contextual-BM25 (anthropics/claude-cookbooks contextual retrieval, the offline BM25 half): a short
    # situating line supplied at record time (target role, what made it reachable, what it chained from/
    # to) is prepended to the body so it flows into the FTS mirror via the triggers - search() then also
    # matches on this context, improving recall for terse findings. Sanitized like all stored text; the
    # marker keeps it distinguishable from the operator's original body. Back-compat: absent -> unchanged.
    ctx = _sanitize(str(finding.get("context", "") or "")).strip()
    if ctx:
        body = f"Context: {ctx}\n\n{body}" if body else f"Context: {ctx}"
    cwe = str(finding.get("cwe", "") or "").upper()
    sev = str(finding.get("severity", "info") or "info").strip().lower()
    if sev not in SEVERITY_RANK:
        raise StoreError(f"invalid severity {sev!r}")
    scope = str(finding.get("scope", "") or "")
    bound = bound_scope(conn)
    if not scope:
        scope = bound                                    # default an unspecified scope to the store's
    if bound and scope != bound:                         # belt-and-suspenders (trigger also guards)
        raise ScopeError(f"finding scope {scope!r} != store scope {bound!r}")
    phase = str(finding.get("phase", "") or "")
    status = str(finding.get("status", "possible") or "possible").strip().lower()
    conf = finding.get("confidence")
    conf = float(conf) if isinstance(conf, (int, float)) and not isinstance(conf, bool) else None
    fid = str(finding.get("fid") or "") or derive_fid(scope, title, cwe)
    when = ts if ts is not None else time.time()
    try:
        existing = conn.execute("SELECT rowid FROM findings WHERE fid=?", (fid,)).fetchone()
        if existing:
            conn.execute(
                "UPDATE findings SET cwe=?, severity=?, title=?, phase=?, scope=?, status=?, "
                "confidence=?, body=?, ts=? WHERE fid=?",
                (cwe, sev, title, phase, scope, status, conf, body, when, fid))
        else:
            conn.execute(
                "INSERT INTO findings(fid, cwe, severity, title, phase, scope, status, confidence, "
                "body, ts) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (fid, cwe, sev, title, phase, scope, status, conf, body, when))
        conn.commit()
    except sqlite3.Error as exc:
        conn.rollback()
        if "scope violation" in str(exc):
            raise ScopeError(str(exc)) from exc
        raise StoreError(str(exc)) from exc
    return fid


# --------------------------------------------------------------------------- 3-layer retrieval
def _compact(row) -> dict:
    return {"fid": row[0], "cwe": row[1], "severity": row[2], "title": row[3],
            "phase": row[4], "status": row[5], "ts": row[6]}

_COMPACT_COLS = "fid, cwe, severity, title, phase, status, ts"
_COMPACT_COLS_F = "f.fid, f.cwe, f.severity, f.title, f.phase, f.status, f.ts"


def _fts_query(query: str) -> str:
    toks = [t for t in "".join(c if c.isalnum() else " " for c in (query or "")).split() if t]
    return " OR ".join(f'"{t}"' for t in toks)


def search(conn: sqlite3.Connection, query: str, *, limit: int = 25) -> list:
    """Layer 1: compact index rows matching `query`, ranked by relevance then severity."""
    q = _fts_query(query)
    if not q:
        return recent(conn, limit=limit)
    if _HAS_FTS5:
        rows = conn.execute(
            f"SELECT {_COMPACT_COLS_F} FROM findings_fts x JOIN findings f ON f.rowid = x.rowid "
            f"WHERE findings_fts MATCH ? ORDER BY bm25(findings_fts), f.ts DESC LIMIT ?",
            (q, max(1, limit))).fetchall()
    else:                                                # defensive LIKE fallback (no FTS5 build)
        toks = [t for t in "".join(c if c.isalnum() else " " for c in query.lower()).split() if t]
        clause = " OR ".join("(LOWER(title) LIKE ? OR LOWER(body) LIKE ?)" for _ in toks)
        params = []
        for t in toks:
            params += [f"%{t}%", f"%{t}%"]
        rows = conn.execute(
            f"SELECT {_COMPACT_COLS} FROM findings WHERE {clause} ORDER BY ts DESC LIMIT ?",
            (*params, max(1, limit))).fetchall()
    rows = sorted(rows, key=lambda r: (SEVERITY_RANK.get(r[2], 0), r[6]), reverse=True)
    return [_compact(r) for r in rows]


def recent(conn: sqlite3.Connection, *, limit: int = 25) -> list:
    rows = conn.execute(f"SELECT {_COMPACT_COLS} FROM findings ORDER BY ts DESC LIMIT ?",
                        (max(1, limit),)).fetchall()
    return [_compact(r) for r in rows]


def timeline(conn: sqlite3.Connection, anchor_fid: str, *, window: int = 5) -> list:
    """Layer 2: the anchor plus up to `window` findings before and after it by time (same phase
    first). Returns compact rows including the anchor; empty if the anchor is unknown."""
    a = conn.execute("SELECT ts, phase FROM findings WHERE fid=?", (anchor_fid,)).fetchone()
    if not a:
        return []
    ats, aphase = a
    before = conn.execute(
        f"SELECT {_COMPACT_COLS} FROM findings WHERE ts < ? OR (ts = ? AND fid < ?) "
        f"ORDER BY ts DESC LIMIT ?", (ats, ats, anchor_fid, max(0, window))).fetchall()
    after = conn.execute(
        f"SELECT {_COMPACT_COLS} FROM findings WHERE ts > ? OR (ts = ? AND fid > ?) "
        f"ORDER BY ts ASC LIMIT ?", (ats, ats, anchor_fid, max(0, window))).fetchall()
    anchor = conn.execute(f"SELECT {_COMPACT_COLS} FROM findings WHERE fid=?", (anchor_fid,)).fetchone()
    ordered = list(reversed(before)) + [anchor] + list(after)
    out = [_compact(r) for r in ordered]
    for r in out:                                        # mark same-phase neighbours + the anchor
        r["same_phase"] = (r["phase"] == aphase)
        r["is_anchor"] = (r["fid"] == anchor_fid)
    return out


def get(conn: sqlite3.Connection, fids: list) -> list:
    """Layer 3: full finding rows (incl. body) for the given ids, in the order requested."""
    if not fids:
        return []
    qmarks = ",".join("?" for _ in fids)
    rows = conn.execute(
        f"SELECT fid, cwe, severity, title, phase, scope, status, confidence, body, ts "
        f"FROM findings WHERE fid IN ({qmarks})", list(fids)).fetchall()
    by_fid = {r[0]: {"fid": r[0], "cwe": r[1], "severity": r[2], "title": r[3], "phase": r[4],
                     "scope": r[5], "status": r[6], "confidence": r[7], "body": r[8], "ts": r[9]}
              for r in rows}
    return [by_fid[f] for f in fids if f in by_fid]      # requested order, skip unknown


# --------------------------------------------------------------------------- token economics
def estimate_tokens(text: str) -> int:
    """Cheap stdlib token estimate (~4 chars/token). An ESTIMATE, not tiktoken."""
    return (len(text or "") + 3) // 4


def recall_cost(conn: sqlite3.Connection, fids: list) -> int:
    """Tokens to read the FULL bodies of these findings (layer-3 cost)."""
    return sum(estimate_tokens(f["title"]) + estimate_tokens(f["body"]) for f in get(conn, fids))


def rediscovery_estimate(conn: sqlite3.Connection) -> int:
    """Labelled ESTIMATE of the tokens it would take to re-derive every stored finding from scratch
    (distilled body tokens x REDISCOVER_FACTOR) - the work the store saves. Not a measurement."""
    total = 0
    for (body, title) in conn.execute("SELECT body, title FROM findings").fetchall():
        total += estimate_tokens(body) + estimate_tokens(title)
    return total * REDISCOVER_FACTOR


def plan_recall(conn: sqlite3.Connection, fids: list, budget: int) -> dict:
    """Fit as many requested findings into a token `budget` as possible, HIGHEST severity first.
    Over-budget ids are LISTED under `dropped` - never silently truncated."""
    rows = get(conn, fids)
    rows.sort(key=lambda f: (SEVERITY_RANK.get(f["severity"], 0), f["ts"]), reverse=True)
    included, dropped, used = [], [], 0
    for f in rows:
        cost = estimate_tokens(f["title"]) + estimate_tokens(f["body"])
        if used + cost <= budget:
            used += cost
            included.append(f["fid"])
        else:
            dropped.append(f["fid"])
    return {"budget": budget, "used": used, "included": included, "dropped": dropped}


def telemetry(conn: sqlite3.Connection) -> dict:
    """Counts/enums only - NEVER content. Safe to log."""
    n = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    by_sev = dict(conn.execute("SELECT severity, COUNT(*) FROM findings GROUP BY severity").fetchall())
    by_status = dict(conn.execute("SELECT status, COUNT(*) FROM findings GROUP BY status").fetchall())
    by_phase = dict(conn.execute("SELECT phase, COUNT(*) FROM findings GROUP BY phase").fetchall())
    body_tokens = sum(estimate_tokens(b) for (b,) in conn.execute("SELECT body FROM findings"))
    return {"findings": n, "by_severity": by_sev, "by_status": by_status, "by_phase": by_phase,
            "stored_body_tokens": body_tokens, "rediscovery_estimate": rediscovery_estimate(conn),
            "scope": bound_scope(conn)}


# --------------------------------------------------------------------------- integrity
def verify_integrity(conn: sqlite3.Connection, *, rebuild: bool = True) -> dict:
    """Compare COUNT(findings) vs COUNT(fts); rebuild the FTS mirror on a mismatch (self-heal)."""
    if not _HAS_FTS5:
        return {"fts5": False, "findings": conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
                "fts": None, "rebuilt": False}
    nf = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    nx = conn.execute("SELECT COUNT(*) FROM findings_fts").fetchone()[0]
    rebuilt = False
    if nf != nx and rebuild:
        conn.execute("DELETE FROM findings_fts")
        conn.execute("INSERT INTO findings_fts(rowid, title, body) SELECT rowid, title, body FROM findings")
        conn.commit()
        rebuilt = True
        nx = conn.execute("SELECT COUNT(*) FROM findings_fts").fetchone()[0]
    return {"fts5": True, "findings": nf, "fts": nx, "rebuilt": rebuilt}


# --------------------------------------------------------------------------- CLI
def _print(obj) -> None:
    print(json.dumps(obj, indent=2))


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(description="Scoped FTS5 finding store with 3-layer retrieval.")
    p.add_argument("--db", required=True)
    sub = p.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("init"); i.add_argument("--scope", default="")
    a = sub.add_parser("add"); a.add_argument("--json", required=True, help="finding JSON, or - for stdin")
    a.add_argument("--scope", default=None)
    s = sub.add_parser("search"); s.add_argument("--query", required=True); s.add_argument("--limit", type=int, default=25)
    t = sub.add_parser("timeline"); t.add_argument("--anchor", required=True); t.add_argument("--window", type=int, default=5)
    g = sub.add_parser("get"); g.add_argument("--ids", required=True); g.add_argument("--budget", type=int)
    sub.add_parser("telemetry")
    sub.add_parser("verify")
    args = p.parse_args(argv)

    try:
        if args.cmd == "init":
            conn = open_store(args.db, scope=args.scope or None, create=True)
            print(f"initialized store {args.db} (scope={bound_scope(conn)!r}, fts5={_HAS_FTS5})")
            conn.close()
            return 0
        if args.cmd == "add":
            raw = sys.stdin.read() if args.json == "-" else args.json
            finding = json.loads(raw)
            conn = open_store(args.db, scope=getattr(args, "scope", None), create=True)
            fid = add_finding(conn, finding)
            conn.close()
            print(f"stored {fid}")
            return 0
        conn = open_store(args.db, create=False)
        try:
            if args.cmd == "search":
                _print(search(conn, args.query, limit=args.limit))
            elif args.cmd == "timeline":
                _print(timeline(conn, args.anchor, window=args.window))
            elif args.cmd == "get":
                ids = [x.strip() for x in args.ids.split(",") if x.strip()]
                if args.budget is not None:
                    plan = plan_recall(conn, ids, args.budget)
                    if plan["dropped"]:
                        print(f"# recall budget {args.budget} tok: {len(plan['included'])} included, "
                              f"{len(plan['dropped'])} OVER BUDGET (not fetched): "
                              f"{','.join(plan['dropped'])}", file=sys.stderr)
                    _print(get(conn, plan["included"]))
                else:
                    _print(get(conn, ids))
            elif args.cmd == "telemetry":
                _print(telemetry(conn))
            elif args.cmd == "verify":
                _print(verify_integrity(conn, rebuild=True))
        finally:
            conn.close()
        return 0
    except ScopeError as exc:
        print(f"scope violation: {exc}", file=sys.stderr)
        return 3
    except (StoreError, json.JSONDecodeError, sqlite3.Error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
