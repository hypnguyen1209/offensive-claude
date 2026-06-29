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


def record(pattern: dict, path: str) -> None:
    schemas.validate_pattern(pattern)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(pattern) + "\n")


def match(records: list, *, vuln_class: Optional[str] = None, tech_stack=None,
          target: Optional[str] = None, top: int = 10) -> list:
    """Filter + rank (highest CVSS/severity, then most recent), return top-N."""
    want_stack = {s.strip().lower() for s in (tech_stack or []) if s.strip()}
    vc = (vuln_class or "").strip().lower()
    tgt = schemas.normalize_target(target) if target else None
    hits = []
    for r in records:
        if vc and r.get("vuln_class") != vc:
            continue
        if tgt and r.get("target") != tgt:
            continue
        if want_stack and not (want_stack & set(r.get("tech_stack", []))):
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

    sub.add_parser("compact")
    sub.add_parser("stats")

    args = p.parse_args(argv)
    db = args.db or default_db()
    try:
        if args.cmd == "record":
            rec = _build_record(args)
            record(rec, db)
            print(f"recorded {schemas.pattern_key(rec)} (severity={rec['severity']} cvss={rec['cvss']})")
            return 0
        if args.cmd == "match":
            hits = match(merged(db), vuln_class=args.vuln_class,
                         tech_stack=(args.tech_stack.split(",") if args.tech_stack else None),
                         target=args.target, top=args.top)
            if args.json:
                print(json.dumps(hits, indent=2))
            else:
                for h in hits:
                    print(f"[{h['severity']:8} cvss={h.get('cvss')}] {h['target']} {h['vuln_class']} "
                          f"{h.get('attack_id','')} {h.get('technique','')} (x{h.get('count',1)})")
                if not hits:
                    print("(no prior patterns match)")
            return 0
        if args.cmd == "compact":
            before, after = rotation.compact(db)
            print(f"compacted {db}: {before} -> {after} records")
            return 0
        if args.cmd == "stats":
            recs = merged(db)
            by_class: dict = {}
            for r in recs:
                by_class[r["vuln_class"]] = by_class.get(r["vuln_class"], 0) + 1
            print(f"db: {db}\npatterns (merged): {len(recs)}")
            for c, n in sorted(by_class.items(), key=lambda kv: -kv[1]):
                print(f"  {n:4}  {c}")
            return 0
    except (ValueError, schemas.SchemaError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
