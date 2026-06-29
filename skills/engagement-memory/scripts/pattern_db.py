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
import os
import sys
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import schemas  # noqa: E402
import rotation  # noqa: E402


def default_db() -> str:
    return os.environ.get("ENGAGEMENT_DB") or os.path.join(
        os.path.expanduser("~"), ".claude", "engagement-memory", "patterns.jsonl")


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


def merged(path: str) -> list:
    """All patterns, duplicates merged by key (highest impact wins, counts summed)."""
    by_key: dict = {}
    for rec in load(path):
        k = schemas.pattern_key(rec)
        by_key[k] = schemas.merge(by_key[k], rec) if k in by_key else rec
    return list(by_key.values())


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


def match(records: list, *, vuln_class: Optional[str] = None, tech_stack=None,
          target: Optional[str] = None, top: int = 10) -> list:
    """Filter + rank (highest CVSS/severity, then most recent), return top-N."""
    want_stack = {s.strip().lower() for s in (tech_stack or []) if s.strip()}
    vc = (vuln_class or "").strip().lower()
    tgt = schemas.normalize_target(target) if target else None
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
        hits.append(r)
    hits.sort(key=schemas.rank_score, reverse=True)
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

    m = sub.add_parser("match")
    m.add_argument("--vuln-class", dest="vuln_class"); m.add_argument("--tech-stack", dest="tech_stack")
    m.add_argument("--target"); m.add_argument("--top", type=int, default=10); m.add_argument("--json", action="store_true")

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
            record(rec, db)
            _emit_audit(db, "write", "record", target=rec.get("target"), note=str(schemas.pattern_key(rec)))
            print(f"recorded {schemas.pattern_key(rec)} (severity={rec['severity']} cvss={rec['cvss']})")
            return 0
        if args.cmd == "match":
            hits = match(merged(db), vuln_class=args.vuln_class,
                         tech_stack=(args.tech_stack.split(",") if args.tech_stack else None),
                         target=args.target, top=args.top)
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
