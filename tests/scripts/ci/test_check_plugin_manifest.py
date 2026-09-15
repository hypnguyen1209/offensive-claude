"""Tests for scripts/ci/check_plugin_manifest.py — the manifest + hook-wiring consistency gate.

Two properties: (1) GREEN on the real shipped tree, and (2) RED (named) on each drift class —
version skew, missing field, unlisted plugin, and a hooks.json reference to a missing hook script.
Drift cases run against a scaffolded temp tree so the repo is never mutated.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts" / "ci"))

import check_plugin_manifest as cpm  # noqa: E402

_REPO = Path(__file__).resolve().parents[3]


# ------------------------------------------------------------------ real tree
def test_real_tree_is_consistent():
    assert cpm.check(_REPO).ok is True


def test_real_tree_via_main():
    assert cpm.main(["--root", str(_REPO)]) == 0


# ------------------------------------------------------------------ scaffold
def _scaffold(root: Path, *, plugin_version="1.0.0", market_version="1.0.0",
              name="demo", list_plugin=True, drop_field=None, hook_script="session-start"):
    (root / ".claude-plugin").mkdir(parents=True)
    plugin = {"name": name, "version": plugin_version, "description": "d"}
    if drop_field:
        plugin.pop(drop_field, None)
    (root / ".claude-plugin" / "plugin.json").write_text(json.dumps(plugin), encoding="utf-8")

    entries = [{"name": name, "version": market_version}] if list_plugin else []
    market = {"name": "m", "plugins": entries}
    (root / ".claude-plugin" / "marketplace.json").write_text(json.dumps(market), encoding="utf-8")

    hooks = root / "hooks"
    hooks.mkdir()
    (hooks / "hooks.json").write_text(json.dumps({
        "hooks": {"SessionStart": [{"hooks": [
            {"type": "command", "command": f'"${{CLAUDE_PLUGIN_ROOT}}/hooks/run-hook.cmd" {hook_script}'}
        ]}]}
    }), encoding="utf-8")
    (hooks / "session-start").write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    return root


def test_clean_scaffold_passes(tmp_path):
    _scaffold(tmp_path)
    assert cpm.check(tmp_path).ok is True


def test_version_drift_flagged(tmp_path):
    _scaffold(tmp_path, plugin_version="1.9.0", market_version="1.8.1")
    rep = cpm.check(tmp_path)
    assert rep.ok is False
    assert any("version drift" in v for v in rep.violations)


def test_missing_required_field_flagged(tmp_path):
    _scaffold(tmp_path, drop_field="description")
    rep = cpm.check(tmp_path)
    assert rep.ok is False
    assert any("description" in v for v in rep.violations)


def test_plugin_not_listed_flagged(tmp_path):
    _scaffold(tmp_path, list_plugin=False)
    rep = cpm.check(tmp_path)
    assert rep.ok is False
    assert any("plugins" in v or "does not list" in v for v in rep.violations)


def test_missing_hook_script_flagged(tmp_path):
    # hooks.json references "subagent-start" but the scaffold only wrote "session-start"
    _scaffold(tmp_path, hook_script="subagent-start")
    rep = cpm.check(tmp_path)
    assert rep.ok is False
    assert any("missing hook script" in v and "subagent-start" in v for v in rep.violations)


def test_broken_manifest_exits_2(tmp_path):
    (tmp_path / ".claude-plugin").mkdir(parents=True)
    (tmp_path / ".claude-plugin" / "plugin.json").write_text("{not json", encoding="utf-8")
    (tmp_path / ".claude-plugin" / "marketplace.json").write_text("{}", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        cpm.check(tmp_path)
    assert exc.value.code == 2


def test_main_json_output(tmp_path, capsys):
    _scaffold(tmp_path, plugin_version="2.0.0", market_version="1.0.0")
    rc = cpm.main(["--root", str(tmp_path), "--json"])
    assert rc == 1
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is False and out["violations"]
