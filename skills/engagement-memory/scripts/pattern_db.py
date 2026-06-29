#!/usr/bin/env python3
"""pattern_db.py - cross-engagement pattern memory (append-only JSONL + ranked recall).

The learning loop: /engage.report writes confirmed findings here; /engage.recon and
/engage.weaponize RECALL the top matches for the target's class/stack so we start from what
already worked. Recall is an EXPLICIT top-N query, never "load everything" - that is the
anti-context-bloat discipline.

Storage: append-only JSONL (crash-safe O(1) writes). Duplicate keys (same target+class+
technique) are merged on read and on compaction - NEVER blind-discarded (compaction keeps the
highest-impact record and bumps its count). Default DB: ~/.claude/engagement-memory/patterns.jsonl
(override with --db or $ENGAGEMENT_DB).

CLI:
  pattern_db.py record --target acme.com --vuln-class ssrf --cwe CWE-918 --severity high --cvss 9.1 \
                       --attack-id T1190 --technique "metadata theft" --tech-stack nginx,aws
  pattern_db.py record --json '<finding json>'        # or '-' to read stdin
  pattern_db.py match  [--vuln-class ssrf] [--tech-stack nginx,aws] [--target acme.com] [--top 10] [--json]
  pattern_db.py compact            # dedup-merge in place (patterns preserved)
  pattern_db.py stats
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
import time
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import schemas  # noqa: E402
import rotation  # noqa: E402

# --------------------------------------------------------------------------- relevance (stdlib BM25)
# Free-text synonym expansion (query<->document vocabulary mismatch) — stdlib, no embeddings.
ALIASES = {
    "ssrf": ["server", "side", "request", "forgery"], "imds": ["metadata", "instance", "169.254.169.254"],
    "idor": ["broken", "object", "level", "authorization", "bola"], "bola": ["idor", "object", "authorization"],
    "rce": ["remote", "code", "execution", "command", "injection"], "lpe": ["local", "privilege", "escalation", "privesc"],
    "privesc": ["privilege", "escalation"], "xss": ["cross", "site", "scripting"], "ad": ["active", "directory"],
    "ntlm": ["relay", "net-ntlm"], "csrf": ["cross", "site", "request", "forgery"], "ssti": ["template", "injection"],
}
_TOKEN = re.compile(r"[a-z0-9]+")


def tokenize(text: str) -> list:
    return _TOKEN.findall((text or "").lower())


def expand_query(terms) -> list:
    out = list(terms)
    for t in terms:
        out += ALIASES.get(t, [])
    return out


def doc_tokens(rec: dict) -> list:
    return tokenize(" ".join([rec.get("technique", ""), rec.get("vuln_class", ""), rec.get("attack_id", ""),
                              rec.get("cwe", ""), " ".join(rec.get("tech_stack", []))]))


def _build_idf(docs: list) -> dict:
    n = len(docs) or 1
    df: dict = {}
    for d in docs:
        for t in set(d):
            df[t] = df.get(t, 0) + 1
    return {t: math.log(1 + (n - c + 0.5) / (c + 0.5)) for t, c in df.items()}


def bm25_score(q_terms: list, dt: list, idf: dict, avgdl: float, k1: float = 1.2, b: float = 0.75) -> float:
    if not dt or avgdl <= 0:
        return 0.0
    dl = len(dt)
    tf: dict = {}
    for t in dt:
        tf[t] = tf.get(t, 0) + 1
    score = 0.0
    for t in set(q_terms):
        f = tf.get(t, 0)
        if f:
            score += idf.get(t, 0.0) * (f * (k1 + 1)) / (f + k1 * (1 - b + b * dl / avgdl))
    return score


def default_db() -> str:
    return os.environ.get("ENGAGEMENT_DB") or os.path.join(
        os.path.expanduser("~"), ".claude", "engagement-memory", "patterns.jsonl")


def global_db() -> str:
    """Cross-client store of SANITIZED techniques (no target/evidence). Per-client isolation is the
    default; the global store is opt-in via `promote --global` / `record --global` / `match --include-global`."""
    return os.environ.get("ENGAGEMENT_GLOBAL_DB") or os.path.join(
        os.path.expanduser("~"), ".claude", "engagement-memory", "global.jsonl")


def _sanitize_for_global(rec: dict) -> dict:
    """Strip client-identifying data before a pattern crosses into the shared global store:
    blank target/evidence/source AND scrub the client's host (and its labels) out of the free-text
    technique, so a client identifier can't ride along in the carrier fields. tech_stack stays
    (generic tech names like nginx/aws are transferable, not client-identifying)."""
    out = dict(rec)
    tgt = rec.get("target", "") or ""
    tech = rec.get("technique", "") or ""
    if tgt:
        tech = re.sub(re.escape(tgt), "<target>", tech, flags=re.I)
        for lab in re.split(r"[.:]", tgt):
            if len(lab) >= 4:
                tech = re.sub(r"\b" + re.escape(lab) + r"\b", "<redacted>", tech, flags=re.I)
    out["technique"] = tech
    out["target"] = "global"
    out["evidence_ref"] = ""
    out["source"] = ""
    out["count"] = 1
    return out


def load(path: str) -> list:
    """Read all valid pattern records (silently skip malformed/foreign lines)."""
    out = []
    if not os.path.isfile(path):
        return out
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                schemas.validate_pattern(rec)
                out.append(rec)
            except (ValueError, schemas.SchemaError):
                continue
    return out


def _apply_staleness(rec: dict, now: float) -> None:
    ttl = int(rec.get("ttl_days") or 0)
    if ttl > 0 and rec.get("status", "active") == "active":
        lv = float(rec.get("last_verified") or rec.get("ts") or 0)
        if now - lv > ttl * 86400:
            rec["status"] = "stale"          # soft decay: downranked, never deleted


def merged(path: str, now: Optional[float] = None) -> list:
    """All patterns, duplicates merged by key (highest impact wins, counts summed). Applies TTL
    staleness (active -> stale once last_verified is older than ttl_days)."""
    now = now if now is not None else time.time()
    by_key: dict = {}
    for rec in load(path):
        k = schemas.pattern_key(rec)
        by_key[k] = schemas.merge(by_key[k], rec) if k in by_key else rec
    out = list(by_key.values())
    for r in out:
        _apply_staleness(r, now)
    return out


def _sibling(path: str, name: str) -> str:
    return os.path.join(os.path.dirname(path) or ".", name)


def audit_path(db: str) -> str:
    """Disposable audit log, a sibling of the pattern store ($ENGAGEMENT_AUDIT overrides)."""
    return os.environ.get("ENGAGEMENT_AUDIT") or _sibling(db, "audit.jsonl")


def profiles_path(db: str) -> str:
    """target_profile records live in their own file so lossless compaction of patterns.jsonl
    can never drop them and pattern recall never mixes them in."""
    return os.environ.get("ENGAGEMENT_PROFILES") or _sibling(db, "profiles.jsonl")


def write_audit(rec: dict, path: str) -> None:
    schemas.validate_audit(rec)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")
    rotation.rotate_audit(path)          # cap the disposable log inline


def load_profiles(path_or_db: str) -> list:
    """Read target_profile records from the profiles file (accepts the patterns-db path)."""
    p = path_or_db if os.path.basename(path_or_db) == "profiles.jsonl" else profiles_path(path_or_db)
    out = []
    if not os.path.isfile(p):
        return out
    with open(p, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                schemas.validate_target_profile(rec)
                out.append(rec)
            except (ValueError, schemas.SchemaError):
                continue
    return out


def recall_profile(target: str, db: str):
    """Newest target_profile for a target (or None)."""
    tgt = schemas.normalize_target(target)
    hits = [r for r in load_profiles(db) if r.get("target") == tgt]
    return max(hits, key=lambda r: float(r.get("ts") or 0)) if hits else None


def record(rec: dict, path: str) -> None:
    """Append a record, routed by type: audit -> audit.jsonl, target_profile -> profiles.jsonl,
    pattern -> the pattern store (then auto-gc, lossless)."""
    rtype = rec.get("type")
    if rtype == "audit":
        write_audit(rec, audit_path(path))
        return
    if rtype == "target_profile":
        schemas.validate_target_profile(rec)
        dest = profiles_path(path)
    else:
        schemas.validate_pattern(rec)
        dest = path
    os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
    with open(dest, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")
    if rtype != "target_profile":
        rotation.maybe_gc(path, audit_path(path))


def _active_first(rec: dict) -> int:
    return 1 if rec.get("status", "active") in schemas.ACTIVE_STATUSES else 0


def match(records: list, *, vuln_class: Optional[str] = None, tech_stack=None,
          target: Optional[str] = None, query: Optional[str] = None,
          status: Optional[str] = None, top: int = 10) -> list:
    """Filter + rank, return top-N. Active/proposed rank above stale; deprecated/archived/rejected
    are excluded by default. With `query`, blend a stdlib BM25 lexical score (after severity)."""
    want_stack = {s.strip().lower() for s in (tech_stack or []) if s.strip()}
    vc = (vuln_class or "").strip().lower()
    tgt = schemas.normalize_target(target) if target else None
    allow = {x.strip().lower() for x in status.split(",")} if status else None

    def status_ok(r):
        s = r.get("status", "active")
        return (s in allow) if allow else (s not in {"deprecated", "archived", "rejected"})

    hits = []
    for r in records:
        if vc and (r.get("vuln_class") or "").strip().lower() != vc:
            continue
        if tgt and schemas.normalize_target(r.get("target", "")) != tgt:
            continue
        if want_stack:
            have = {s.strip().lower() for s in r.get("tech_stack", []) if isinstance(s, str)}
            if not (want_stack & have):
                continue
        if not status_ok(r):
            continue
        hits.append(r)

    if query:
        q = expand_query(tokenize(query))
        docs = [doc_tokens(r) for r in hits]
        idf = _build_idf(docs)
        avgdl = (sum(len(d) for d in docs) / len(docs)) if docs else 0.0
        scored = [(r, bm25_score(q, doc_tokens(r), idf, avgdl)) for r in hits]
        scored.sort(key=lambda rs: (_active_first(rs[0]), schemas.SEVERITY_RANK.get(rs[0].get("severity"), 0),
                                    round(rs[1], 3)) + schemas.rank_score(rs[0])[1:], reverse=True)
        return [r for r, _ in scored[:max(0, top)]]

    hits.sort(key=lambda r: (_active_first(r),) + schemas.rank_score(r), reverse=True)
    return hits[:max(0, top)]


# --------------------------------------------------------------------------- CLI
def _build_record(args) -> dict:
    if args.json is not None:
        raw = sys.stdin.read() if args.json == "-" else args.json
        data = json.loads(raw)
        # accept a finding-shaped object too
        return schemas.make_pattern(
            target=data.get("target", ""), vuln_class=data.get("vuln_class") or data.get("class", ""),
            cwe=data.get("cwe", ""), attack_id=data.get("attack_id") or data.get("attck_id", ""),
            technique=data.get("technique", ""), severity=data.get("severity", "medium"),
            cvss=data.get("cvss"), tech_stack=data.get("tech_stack"),
            evidence_ref=data.get("evidence_ref") or (data.get("evidence") or [""])[0] if isinstance(data.get("evidence"), list) else data.get("evidence_ref", ""),
            source=data.get("source", ""))
    return schemas.make_pattern(
        target=args.target, vuln_class=args.vuln_class, cwe=args.cwe or "",
        attack_id=args.attack_id or "", technique=args.technique or "", severity=args.severity,
        cvss=args.cvss, tech_stack=(args.tech_stack.split(",") if args.tech_stack else None),
        evidence_ref=args.evidence_ref or "", source=args.source or "")


def _emit_audit(db: str, action_class: str, tool: str, *, target=None, outcome="success", note=""):
    """Best-effort audit line; never let auditing break the underlying operation."""
    try:
        write_audit(schemas.make_audit(action_class, tool, target=target, outcome=outcome, note=note),
                    audit_path(db))
    except Exception:
        pass


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(description="Cross-engagement pattern memory.")
    p.add_argument("--db", default=None)
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("record")
    r.add_argument("--target"); r.add_argument("--vuln-class", dest="vuln_class")
    r.add_argument("--cwe"); r.add_argument("--attack-id", dest="attack_id")
    r.add_argument("--technique"); r.add_argument("--severity", default="medium")
    r.add_argument("--cvss", type=float); r.add_argument("--tech-stack", dest="tech_stack")
    r.add_argument("--evidence-ref", dest="evidence_ref"); r.add_argument("--source")
    r.add_argument("--json", nargs="?", const="-")
    r.add_argument("--resolve", choices=["update", "merge", "reject", "force"],
                   help="resolve a key collision (else review_required)")
    r.add_argument("--reason", default="")
    r.add_argument("--global", dest="to_global", action="store_true", help="also write a sanitized copy to the global store")

    m = sub.add_parser("match")
    m.add_argument("--vuln-class", dest="vuln_class"); m.add_argument("--tech-stack", dest="tech_stack")
    m.add_argument("--target"); m.add_argument("--query"); m.add_argument("--status")
    m.add_argument("--include-global", dest="include_global", action="store_true")
    m.add_argument("--top", type=int, default=10); m.add_argument("--json", action="store_true")

    inj = sub.add_parser("inject", help="budgeted prior-intel card for a phase (top-N, byte-capped)")
    inj.add_argument("--vuln-class", dest="vuln_class"); inj.add_argument("--tech-stack", dest="tech_stack")
    inj.add_argument("--target"); inj.add_argument("--query")
    inj.add_argument("--top", type=int, default=3); inj.add_argument("--max-bytes", dest="max_bytes", type=int, default=1500)

    for verb in ("promote", "deprecate"):
        v = sub.add_parser(verb, help=f"{verb} a pattern by its (target, vuln_class, technique) key")
        v.add_argument("--target", required=True); v.add_argument("--vuln-class", dest="vuln_class", required=True)
        v.add_argument("--technique", default="")
        v.add_argument("--global", dest="to_global", action="store_true", help="(promote) also publish a sanitized copy to the global store")

    pr = sub.add_parser("profile", help="record a target_profile (durable per-target facts)")
    pr.add_argument("--target", required=True); pr.add_argument("--tech-stack", dest="tech_stack")
    pr.add_argument("--endpoints"); pr.add_argument("--notes", default="")

    rp = sub.add_parser("recall-profile"); rp.add_argument("--target", required=True)
    rp.add_argument("--json", action="store_true")

    sub.add_parser("compact")
    sub.add_parser("stats")
    sub.add_parser("audit-stats")

    args = p.parse_args(argv)
    db = args.db or default_db()
    try:
        if args.cmd == "record":
            rec = _build_record(args)
            key = schemas.pattern_key(rec)
            existing = next((r for r in merged(db) if schemas.pattern_key(r) == key), None)
            if existing is not None and not args.resolve:
                # human-in-the-loop: a key collision is not silently merged
                _emit_audit(db, "write", "record", target=rec.get("target"), outcome="denial", note="review_required")
                print(json.dumps({"review_required": True, "key": list(key),
                                  "existing": {k: existing.get(k) for k in ("status", "severity", "cvss", "count")},
                                  "hint": "re-run with --resolve update|merge|reject|force"}))
                return 0
            if args.resolve == "reject":
                rec["status"] = "rejected"
                rec["rejected_reason"] = args.reason or "rejected on review"
                rec["last_verified"] = schemas._now(None)
            record(rec, db)
            if args.to_global:
                record(_sanitize_for_global(rec), global_db())
                _emit_audit(db, "admin", "record-global", note=str(key))
            _emit_audit(db, "write", "record", target=rec.get("target"), note=str(key))
            print(f"recorded {key} (status={rec.get('status')} severity={rec['severity']} cvss={rec['cvss']})")
            return 0
        if args.cmd == "match":
            pool = merged(db) + (merged(global_db()) if args.include_global else [])
            hits = match(pool, vuln_class=args.vuln_class,
                         tech_stack=(args.tech_stack.split(",") if args.tech_stack else None),
                         target=args.target, query=args.query, status=args.status, top=args.top)
            _emit_audit(db, "read", "match", target=args.target, note=f"{len(hits)} hits")
            if args.json:
                print(json.dumps(hits, indent=2))
            else:
                for h in hits:
                    print(f"[{h['severity']:8} cvss={h.get('cvss')}] {h['target']} {h['vuln_class']} "
                          f"{h.get('attack_id','')} {h.get('technique','')} (x{h.get('count',1)})")
                if not hits:
                    print("(no prior patterns match)")
            return 0
        if args.cmd == "inject":
            mode = os.environ.get("ENGAGEMENT_MEMORY_MODE", "auto").lower()
            if mode == "off":
                return 0
            hits = match(merged(db), vuln_class=args.vuln_class, target=args.target, query=args.query,
                         tech_stack=(args.tech_stack.split(",") if args.tech_stack else None), top=args.top)
            _emit_audit(db, "read", "inject", target=args.target, note=f"{len(hits)} hits")
            if not hits:
                print("(no prior intel for this scope)")
                return 0
            lines, used = ["## Prior intel (engagement-memory)"], 0
            for h in hits:
                tag = "" if h.get("status", "active") == "active" else f" [{h.get('status')}]"
                ln = (f"- {h.get('attack_id','')} {h['vuln_class']}: {h.get('technique','')} "
                      f"(sev={h['severity']} cvss={h.get('cvss')} x{h.get('count',1)} "
                      f"conf={h.get('confidence',1.0)}){tag}")
                if used + len(ln) > args.max_bytes:
                    break
                lines.append(ln); used += len(ln)
            if mode == "debug":
                lines.append(f"<!-- mode=debug, {len(hits)} candidates, ~{used}B used -->")
            print("\n".join(lines))
            return 0
        if args.cmd in ("promote", "deprecate"):
            key = (schemas.normalize_target(args.target), (args.vuln_class or "").strip().lower(),
                   (args.technique or "").strip().lower())
            cur = next((r for r in merged(db) if schemas.pattern_key(r) == key), None)
            if cur is None:
                print(f"no pattern for key {key}", file=sys.stderr)
                return 2
            newrec = dict(cur)
            newrec["status"] = "active" if args.cmd == "promote" else "deprecated"
            newrec["last_verified"] = schemas._now(None)
            newrec["count"] = 1                    # status-change line, not a reconfirmation
            record(newrec, db)                     # append-only; merge resolves status by recency
            if args.cmd == "promote" and getattr(args, "to_global", False):
                record(_sanitize_for_global(newrec), global_db())
                _emit_audit(db, "admin", "promote-global", target="global", note=str(key))
            _emit_audit(db, "admin", args.cmd, target=newrec["target"], note=str(key))
            print(f"{args.cmd}d {key} -> status={newrec['status']}")
            return 0
        if args.cmd == "profile":
            rec = schemas.make_target_profile(
                args.target, tech_stack=(args.tech_stack.split(",") if args.tech_stack else None),
                endpoints=(args.endpoints.split(",") if args.endpoints else None), notes=args.notes)
            record(rec, db)
            _emit_audit(db, "write", "profile", target=rec.get("target"))
            print(f"recorded target_profile for {rec['target']}")
            return 0
        if args.cmd == "recall-profile":
            prof = recall_profile(args.target, db)
            print(json.dumps(prof, indent=2) if (args.json or prof) else "(no profile)")
            return 0
        if args.cmd == "compact":
            before, after = rotation.compact(db)
            _emit_audit(db, "admin", "compact", note=f"{before}->{after}")
            print(f"compacted {db}: {before} -> {after} records")
            return 0
        if args.cmd == "stats":
            recs = merged(db)
            by_class: dict = {}
            for rec in recs:
                by_class[rec["vuln_class"]] = by_class.get(rec["vuln_class"], 0) + 1
            print(f"db: {db}\npatterns (merged): {len(recs)} | profiles: {len(load_profiles(db))}")
            for c, n in sorted(by_class.items(), key=lambda kv: -kv[1]):
                print(f"  {n:4}  {c}")
            return 0
        if args.cmd == "audit-stats":
            by_tool, by_action, by_outcome = {}, {}, {}
            total = 0
            ap = audit_path(db)
            if os.path.isfile(ap):
                with open(ap, "r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            ev = json.loads(line)
                        except ValueError:
                            continue
                        if ev.get("type") != "audit":
                            continue
                        total += 1
                        by_tool[ev.get("tool", "?")] = by_tool.get(ev.get("tool", "?"), 0) + 1
                        by_action[ev.get("action_class", "?")] = by_action.get(ev.get("action_class", "?"), 0) + 1
                        by_outcome[ev.get("outcome", "?")] = by_outcome.get(ev.get("outcome", "?"), 0) + 1
            print(f"audit: {ap}\nevents: {total}")
            print("  by tool:    " + ", ".join(f"{k}={v}" for k, v in sorted(by_tool.items())))
            print("  by action:  " + ", ".join(f"{k}={v}" for k, v in sorted(by_action.items())))
            print("  by outcome: " + ", ".join(f"{k}={v}" for k, v in sorted(by_outcome.items())))
            return 0
    except (ValueError, schemas.SchemaError) as exc:
        _emit_audit(db, "write", args.cmd, outcome="denial", note=str(exc)[:120])
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        _emit_audit(db, "write", args.cmd, outcome="error", note=str(exc)[:120])
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
