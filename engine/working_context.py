#!/usr/bin/env python3
"""working_context.py - render the living WORKING-CONTEXT.md engagement-state file (ecc).

A human-readable snapshot of "where the engagement stands right now" - distinct from the machine
finding store (finding_store.py). `/engage.status` surfaces it. It answers, at a glance:

  * Current truth   - bound scope + active kill-chain phase.
  * Constraints     - ROE / boundaries the operator must not cross.
  * Active queues   - what is in flight (open leads, a validation worklist, blocked items).
  * Finding index   - the COMPACT layer-1 view only (severity / cwe / title / status), never bodies -
                      so this file stays cheap to read even late in a long engagement.
  * Recall economics - the finding store's counts + its rediscovery-vs-recall estimate (why memory
                      beats re-deriving), straight from telemetry (counts/enums only).

Operator free-text (constraints, queue items) is run through the SAME write-boundary redaction as the
finding store - `<private>` spans stripped, credential shapes masked - because this file persists too.

CLI:
  working_context.py --db f.db --phase exploit \\
      --constraint "no DoS" --constraint "prod read-only" \\
      --queue "leads=SSRF webhook,IDOR /api/users" --queue "blocked=needs VPN" \\
      --out .engage/WORKING-CONTEXT.md [--top 20]
Exit: 0 ok, 2 error.
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
_LIB = os.path.join(_HERE, "..", "skills", "coding-mastery", "scripts", "_lib")
sys.path.insert(0, os.path.abspath(_LIB))
import finding_store as fstore  # noqa: E402
import private_tag  # noqa: E402
import secret_scan  # noqa: E402

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "informational": 4}


def _cell(text: str) -> str:
    """Keep a value on one well-formed markdown table cell (escape pipes, flatten newlines)."""
    return str(text).replace("\r", " ").replace("\n", " ").replace("|", "\\|")


def _sanitize(text: str) -> str:
    """Same boundary redaction the finding store applies: private spans, then credential shapes."""
    clean, _ = private_tag.strip_private(text or "")
    clean = clean or ""
    hits = secret_scan.scan(clean)
    if not hits:
        return clean
    by_line: dict = {}
    for h in hits:
        by_line.setdefault(h.line, []).append(h.rule)
    lines = clean.splitlines() or [clean]
    for ln, rules in by_line.items():
        if 1 <= ln <= len(lines):
            lines[ln - 1] = f"[REDACTED secret: {', '.join(sorted(set(rules)))}]"
    return "\n".join(lines)


def render(*, scope: str = "", phase: str = "", constraints: Optional[list] = None,
           queues: Optional[dict] = None, findings: Optional[list] = None,
           telemetry: Optional[dict] = None, updated: str = "") -> str:
    """Build the WORKING-CONTEXT.md markdown. `findings` are COMPACT rows (no bodies). Deterministic:
    pass `updated` explicitly if you want a timestamp line (kept out by default so output is testable)."""
    out = ["# WORKING CONTEXT", ""]
    out.append("## Current truth")
    out.append(f"- Scope: `{_sanitize(scope) or '(unbound)'}`")
    out.append(f"- Phase: {_sanitize(phase) or '(not set)'}")
    if updated:
        out.append(f"- Updated: {_sanitize(updated)}")
    out.append("")

    out.append("## Constraints (ROE)")
    cons = [c for c in (constraints or []) if str(c).strip()]
    if cons:
        out += [f"- {_sanitize(str(c))}" for c in cons]
    else:
        out.append("- _none recorded — confirm ROE before any outward action_")
    out.append("")

    out.append("## Active queues")
    q = {k: [i for i in v if str(i).strip()] for k, v in (queues or {}).items()}
    if any(q.values()):
        for name, items in q.items():
            out.append(f"### {_sanitize(str(name))} ({len(items)})")
            out += [f"- [ ] {_sanitize(str(i))}" for i in items] or ["- _empty_"]
    else:
        out.append("- _no active queues_")
    out.append("")

    out.append("## Finding index (compact)")
    rows = sorted(findings or [], key=lambda f: (_SEV_ORDER.get(f.get("severity"), 5),
                                                 str(f.get("title", ""))))
    if rows:
        out.append("| sev | cwe | status | title | fid |")
        out.append("| --- | --- | --- | --- | --- |")
        for f in rows:
            out.append(f"| {_cell(f.get('severity',''))} | {_cell(f.get('cwe',''))} "
                       f"| {_cell(f.get('status',''))} | {_cell(_sanitize(str(f.get('title',''))))} "
                       f"| `{_cell(f.get('fid',''))}` |")
    else:
        out.append("- _no findings recorded yet_")
    out.append("")

    if telemetry:
        out.append("## Recall economics")
        out.append(f"- Findings stored: {telemetry.get('findings', 0)} "
                   f"({', '.join(f'{k}={v}' for k, v in sorted((telemetry.get('by_severity') or {}).items()))})")
        out.append(f"- Stored body tokens: ~{telemetry.get('stored_body_tokens', 0)} | "
                   f"rediscovery estimate: ~{telemetry.get('rediscovery_estimate', 0)} "
                   f"(reading memory is the cheaper path)")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def from_store(conn, *, scope: str = "", phase: str = "", constraints: Optional[list] = None,
               queues: Optional[dict] = None, top: int = 20, updated: str = "") -> str:
    """Pull the compact finding index + telemetry from an open finding store and render."""
    bound = fstore.bound_scope(conn)
    tel = fstore.telemetry(conn)
    rows = fstore.recent(conn, limit=max(1, top))
    return render(scope=scope or bound, phase=phase, constraints=constraints, queues=queues,
                  findings=rows, telemetry=tel, updated=updated)


def update(path: str, text: str) -> None:
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _parse_queue(spec: str) -> tuple:
    name, _, rest = spec.partition("=")
    items = [x.strip() for x in rest.split(",") if x.strip()]
    return name.strip() or "queue", items


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(description="Render WORKING-CONTEXT.md from engagement state.")
    p.add_argument("--db", help="finding store to pull the compact index + telemetry from")
    p.add_argument("--scope", default="")
    p.add_argument("--phase", default="")
    p.add_argument("--constraint", action="append", default=[], dest="constraints")
    p.add_argument("--queue", action="append", default=[], dest="queues", help="name=item1,item2")
    p.add_argument("--updated", default="")
    p.add_argument("--top", type=int, default=20)
    p.add_argument("--out", default=".engage/WORKING-CONTEXT.md")
    p.add_argument("--stdout", action="store_true", help="print instead of writing --out")
    args = p.parse_args(argv)

    queues: dict = {}
    for spec in args.queues:
        name, items = _parse_queue(spec)
        queues.setdefault(name, []).extend(items)

    try:
        if args.db:
            conn = fstore.open_store(args.db, create=False)
            try:
                text = from_store(conn, scope=args.scope, phase=args.phase,
                                  constraints=args.constraints, queues=queues, top=args.top,
                                  updated=args.updated)
            finally:
                conn.close()
        else:
            text = render(scope=args.scope, phase=args.phase, constraints=args.constraints,
                          queues=queues, updated=args.updated)
    except (fstore.StoreError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.stdout:
        sys.stdout.write(text)
    else:
        try:
            update(args.out, text)
        except OSError as exc:
            print(f"error: cannot write {args.out}: {exc}", file=sys.stderr)
            return 2
        print(f"wrote {args.out} ({len(text)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
