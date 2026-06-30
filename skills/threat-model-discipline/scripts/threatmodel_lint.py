#!/usr/bin/env python3
"""threatmodel_lint.py - enforce a complete threat model, and detect DRIFT across a re-run.

Two jobs:
  1. LINT a threat model (JSON) for the fields a usable model must have - trust boundaries, assets,
     entry points, ATT&CK techniques, mitigations - and reject placeholder/empty content.
  2. DRIFT: diff an updated model against the reviewed baseline. A NEW entry point / asset / trust
     boundary that wasn't in the reviewed model is UNREVIEWED attack surface - the novel value for
     long-running engagements. `/engage.gate` runs drift and refuses to advance on un-acknowledged drift.

Threat model JSON shape (materialized from recon-osint; see templates/threat-model/):
  {"assets":[...], "entry_points":[...], "trust_boundaries":[...],
   "attck":["T1190", ...], "mitigations":[...]}

Pure stdlib. CLI:
  threatmodel_lint.py lint  model.json                 # exit 1 if incomplete
  threatmodel_lint.py drift baseline.json new.json [--json out]   # exit 1 if un-acknowledged drift
"""
from __future__ import annotations

import argparse
import json
import re
import sys

REQUIRED_LISTS = ("assets", "entry_points", "trust_boundaries", "attck", "mitigations")
# surfaces where a newly-appeared item means unreviewed attack surface (drift that must be re-reviewed)
DRIFT_SURFACES = ("entry_points", "assets", "trust_boundaries")
_PLACEHOLDER = re.compile(
    r"^\s*(tbd|tba|tbc|todo|fixme|placeholder|none|n/?a|fill[\s_-]?in|xxx+|\[.*\]|<.*>|[.\-?]+)\s*$", re.I)
_ATTCK = re.compile(r"^T\d{4}(\.\d{3})?$")


def _as_items(v):
    if isinstance(v, list):
        return [str(x) for x in v]
    return []


def lint(model: dict) -> list:
    """Return a list of issues; empty == complete."""
    issues = []
    if not isinstance(model, dict):
        return ["threat model must be a JSON object"]
    for key in REQUIRED_LISTS:
        v = model.get(key)
        if not isinstance(v, list) or not v:
            issues.append(f"'{key}' is missing or empty")
            continue
        for item in v:
            if not isinstance(item, str) or not item.strip() or _PLACEHOLDER.match(item):
                issues.append(f"'{key}' has a placeholder/empty entry: {item!r}")
    for tid in _as_items(model.get("attck")):
        if not _ATTCK.match(tid.strip()):
            issues.append(f"'attck' entry is not a valid technique id (Txxxx): {tid!r}")
    return issues


def drift(baseline: dict, updated: dict) -> dict:
    """Diff updated vs baseline on the drift surfaces. Added items on a surface = unreviewed."""
    if not isinstance(baseline, dict) or not isinstance(updated, dict):
        raise ValueError("both threat models must be JSON objects")
    # A drift surface supplied as a non-list (dict/string/number) would make _as_items() return []
    # and HIDE every added item -> fail-open. Reject it so a malformed model fails CLOSED (exit 2).
    for surface in DRIFT_SURFACES:
        for label, m in (("baseline", baseline), ("updated", updated)):
            v = m.get(surface)
            if v is not None and not isinstance(v, list):
                raise ValueError(f"{label} '{surface}' must be a list, got {type(v).__name__}")
            # items must be strings: an int 5150 vs str '5150' would str-collide and hide a type-change
            if isinstance(v, list) and any(not isinstance(x, str) for x in v):
                raise ValueError(f"{label} '{surface}' has a non-string entry - fail closed")
    report = {"added": {}, "removed": {}, "has_drift": False}
    for surface in DRIFT_SURFACES:
        base = set(_as_items(baseline.get(surface)))
        new = set(_as_items(updated.get(surface)))
        added = sorted(new - base)
        removed = sorted(base - new)
        if added:
            report["added"][surface] = added
        if removed:
            report["removed"][surface] = removed
    # only ADDED surface items are drift that blocks the gate (new unreviewed surface);
    # removed items are recorded but don't block (surface shrank).
    report["has_drift"] = any(report["added"].values())
    report["unreviewed_surface"] = sorted(
        f"{s}:{item}" for s, items in report["added"].items() for item in items)
    return report


def _load(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Lint a threat model + detect drift across a re-run.")
    sub = p.add_subparsers(dest="cmd", required=True)
    li = sub.add_parser("lint"); li.add_argument("model")
    dr = sub.add_parser("drift"); dr.add_argument("baseline"); dr.add_argument("updated"); dr.add_argument("--json")
    args = p.parse_args(argv)
    try:
        if args.cmd == "lint":
            issues = lint(_load(args.model))
            if issues:
                for i in issues:
                    print(f"  - {i}")
                print(f"\nthreat model INCOMPLETE: {len(issues)} issue(s)")
                return 1
            print("threat model complete: all required fields present")
            return 0
        if args.cmd == "drift":
            rep = drift(_load(args.baseline), _load(args.updated))
            if args.json:
                with open(args.json, "w", encoding="utf-8") as fh:
                    json.dump(rep, fh, indent=2)
            if rep["has_drift"]:
                print("DRIFT - unreviewed attack surface added since baseline:")
                for item in rep["unreviewed_surface"]:
                    print(f"  + {item}")
                print("\nre-review the threat model before advancing (or acknowledge the new surface).")
                return 1
            print("no drift on entry_points/assets/trust_boundaries")
            return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
