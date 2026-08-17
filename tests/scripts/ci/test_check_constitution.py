"""Tests for scripts/ci/check_constitution.py — the agent-guardrail floor.

Green on the real tree; red when an agent is missing a required guardrail; the scope
rule is conditional on the forked-discipline marker so the two blind judges are exempt.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts" / "ci"))

import check_constitution as cc  # noqa: E402

_REPO = Path(__file__).resolve().parents[3]


def test_real_tree_passes():
    assert cc.check(_REPO) == []


def test_cli_green_on_real_tree():
    assert cc.main(["--root", str(_REPO)]) == 0


def _make_agent(tmp_path, name, body):
    d = tmp_path / "agents"
    d.mkdir(exist_ok=True)
    (d / name).write_text(body, encoding="utf-8")


def _make_claude(tmp_path):
    (tmp_path / "CLAUDE.md").write_text(
        "[CONFIRMED] scope_guard.py finding-evidence-standards.md authorized", encoding="utf-8")


def test_agent_missing_guardrail_flagged(tmp_path):
    _make_claude(tmp_path)
    _make_agent(tmp_path, "bad.md", "This agent has no guardrail language at all.")
    rules = [cc.Rule("agents/*.md", any_of_groups=(cc._GUARDRAIL,))]
    v = cc.check(tmp_path, rules)
    assert len(v) == 1 and v[0].file == "agents/bad.md"


def test_forked_agent_missing_scope_flagged(tmp_path):
    _make_claude(tmp_path)
    # carries the forked marker but no scope reference -> must be flagged
    _make_agent(tmp_path, "forked.md", "you run forked but I forgot to state scope. OPSEC noted.")
    rules = [cc.Rule("agents/*.md", any_of_groups=(cc._SCOPE,), when_contains="you run forked")]
    v = cc.check(tmp_path, rules)
    assert len(v) == 1 and v[0].file == "agents/forked.md"


def test_blind_judge_exempt_from_scope(tmp_path):
    _make_claude(tmp_path)
    # no forked marker, no scope -> scope rule does NOT apply; only guardrail required
    _make_agent(tmp_path, "blind.md", "A blind checker. Uses finding-evidence-standards.md as bar.")
    rules = [
        cc.Rule("agents/*.md", any_of_groups=(cc._GUARDRAIL,)),
        cc.Rule("agents/*.md", any_of_groups=(cc._SCOPE,), when_contains="you run forked"),
    ]
    assert cc.check(tmp_path, rules) == []


def test_claude_missing_substring_flagged(tmp_path):
    (tmp_path / "CLAUDE.md").write_text("[CONFIRMED] authorized only", encoding="utf-8")
    rules = [cc.Rule("CLAUDE.md", all_of=("[CONFIRMED]", "scope_guard.py"))]
    v = cc.check(tmp_path, rules)
    assert len(v) == 1 and "scope_guard.py" in v[0].rule


def test_no_files_matched_is_a_violation(tmp_path):
    rules = [cc.Rule("agents/*.md", any_of_groups=(cc._GUARDRAIL,))]
    v = cc.check(tmp_path, rules)
    assert len(v) == 1 and "no files matched" in v[0].rule


def test_cli_exit_1_on_violation(tmp_path):
    (tmp_path / "CLAUDE.md").write_text("incomplete", encoding="utf-8")
    # default RULES include the CLAUDE.md all_of, which this file fails
    assert cc.main(["--root", str(tmp_path)]) == 1
