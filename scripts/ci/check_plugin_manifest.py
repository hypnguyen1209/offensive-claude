#!/usr/bin/env python3
"""check_plugin_manifest.py - fail-closed consistency gate for the plugin manifests + hook wiring.

A pure-stdlib complement to `claude plugin validate` (the authoritative validator, run locally /
at release via scripts/ci/validate_plugin.sh). This gate needs no external CLI, so it runs in the
same `consistency` CI job as the other gates and catches the drift classes that bite a released
plugin:

  1. `.claude-plugin/plugin.json` and `.claude-plugin/marketplace.json` parse as JSON.
  2. plugin.json carries the required fields (name, version, description).
  3. The marketplace lists this plugin, and its name matches plugin.json.
  4. **Version sync** - plugin.json.version == the marketplace entry's version. (Both were bumped
     by hand at every release; a gate stops them silently diverging.)
  5. **Hook wiring integrity** - every `run-hook.cmd <name>` in hooks/hooks.json names a hook script
     that actually exists in hooks/ (a typo like a missing `subagent-start` would otherwise ship).

Exit: 0 all consistent, 1 a violation (named), 2 a structural error (missing/unreadable manifest).

CLI:
  check_plugin_manifest.py
  check_plugin_manifest.py --json
  check_plugin_manifest.py --root /path/to/plugin
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# repo root = two levels up from scripts/ci/
_ROOT = Path(__file__).resolve().parents[2]

_REQUIRED_PLUGIN_FIELDS = ("name", "version", "description")
# matches:  ...run-hook.cmd" session-start   /   ...run-hook.cmd" subagent-start
_HOOK_CMD_RE = re.compile(r"run-hook\.cmd\"?\s+([A-Za-z0-9._-]+)")


@dataclass
class Report:
    ok: bool = True
    violations: list = field(default_factory=list)

    def fail(self, msg: str) -> None:
        self.ok = False
        self.violations.append(msg)

    def to_dict(self) -> dict:
        return {"ok": self.ok, "violations": self.violations}


def _load_json(path: Path) -> object:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def check(root: Optional[Path] = None) -> Report:
    root = Path(root) if root else _ROOT
    rep = Report()

    plugin_path = root / ".claude-plugin" / "plugin.json"
    market_path = root / ".claude-plugin" / "marketplace.json"

    # (1) manifests parse ------------------------------------------------------------------
    try:
        plugin = _load_json(plugin_path)
    except (OSError, ValueError) as exc:
        raise SystemExit(_die(f"cannot read/parse {plugin_path}: {exc}"))
    try:
        market = _load_json(market_path)
    except (OSError, ValueError) as exc:
        raise SystemExit(_die(f"cannot read/parse {market_path}: {exc}"))

    if not isinstance(plugin, dict) or not isinstance(market, dict):
        raise SystemExit(_die("manifests must be JSON objects"))

    # (2) required fields ------------------------------------------------------------------
    for f in _REQUIRED_PLUGIN_FIELDS:
        if not plugin.get(f):
            rep.fail(f"plugin.json missing required field: {f}")

    # (3)+(4) marketplace lists this plugin, name + version in sync ------------------------
    name = plugin.get("name")
    version = plugin.get("version")
    entries = market.get("plugins")
    if not isinstance(entries, list) or not entries:
        rep.fail("marketplace.json has no 'plugins' array")
    else:
        match = next((e for e in entries if isinstance(e, dict) and e.get("name") == name), None)
        if match is None:
            rep.fail(f"marketplace.json does not list a plugin named {name!r}")
        else:
            mver = match.get("version")
            if mver != version:
                rep.fail(f"version drift: plugin.json={version!r} but marketplace entry={mver!r}")

    # (5) hook wiring integrity ------------------------------------------------------------
    hooks_path = root / "hooks" / "hooks.json"
    if hooks_path.is_file():
        try:
            hooks = _load_json(hooks_path)
        except (OSError, ValueError) as exc:
            rep.fail(f"hooks/hooks.json does not parse: {exc}")
            hooks = {}
        for event, groups in (hooks.get("hooks") or {}).items():
            for group in groups or []:
                for h in (group.get("hooks") or []):
                    cmd = h.get("command", "")
                    m = _HOOK_CMD_RE.search(cmd)
                    if not m:
                        continue
                    script = m.group(1)
                    if not (root / "hooks" / script).is_file():
                        rep.fail(f"{event}: hooks.json references missing hook script hooks/{script}")

    return rep


def _die(msg: str) -> int:
    print(f"error: {msg}", file=sys.stderr)
    return 2


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(description="Fail-closed plugin-manifest + hook-wiring consistency gate.")
    p.add_argument("--root", default=None, help="plugin root (default: repo root)")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    rep = check(Path(args.root) if args.root else None)

    if args.json:
        print(json.dumps(rep.to_dict(), indent=2))
    elif rep.ok:
        print("ok: plugin manifests + hook wiring consistent")
    else:
        for v in rep.violations:
            print(f"DRIFT {v}", file=sys.stderr)
        print("(fix the manifests / hook wiring, then re-run)", file=sys.stderr)

    return 0 if rep.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
