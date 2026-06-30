"""Tests for dangling_commit_finder - recover force-pushed/orphaned commits from a repo clone.

Run: pytest tests/scripts/incident-response/test_dangling_commit_finder.py
"""
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "skills" / "incident-response" / "scripts"))

import pytest  # noqa: E402
import dangling_commit_finder as dcf  # noqa: E402

HAVE_GIT = shutil.which("git") is not None
needs_git = pytest.mark.skipif(not HAVE_GIT, reason="git not on PATH")


def _git(repo, *args):
    subprocess.run(["git", "-c", "user.email=t@t.test", "-c", "user.name=tester",
                    "-c", "commit.gpgsign=false", "-C", str(repo), *args],
                   check=True, capture_output=True, text=True)


def _rev(repo, ref="HEAD"):
    return subprocess.run(["git", "-C", str(repo), "rev-parse", ref],
                          capture_output=True, text=True).stdout.strip()


@needs_git
def test_recovers_orphaned_malicious_commit(tmp_path):
    repo = tmp_path / "r"; repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "a.txt").write_text("legit", encoding="utf-8")
    _git(repo, "add", "."); _git(repo, "commit", "-qm", "initial")
    (repo / "evil.txt").write_text("backdoor", encoding="utf-8")
    _git(repo, "add", "."); _git(repo, "commit", "-qm", "inject backdoor")
    evil = _rev(repo)
    _git(repo, "reset", "--hard", "HEAD~1")    # force-push simulation: evil now unreachable from refs

    report = dcf.analyze(str(repo))
    shas = [c["sha"] for c in report["dangling_commits"]]
    assert evil in shas, f"orphaned commit {evil[:12]} should be recovered, got {shas}"
    assert any("inject backdoor" in c["subject"] for c in report["dangling_commits"])
    assert report["dangling_count"] >= 1


@needs_git
def test_clean_repo_has_no_dangling(tmp_path):
    repo = tmp_path / "clean"; repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "a.txt").write_text("x", encoding="utf-8")
    _git(repo, "add", "."); _git(repo, "commit", "-qm", "only commit")
    report = dcf.analyze(str(repo))
    assert report["dangling_count"] == 0


@needs_git
def test_reflog_rewrite_detected(tmp_path):
    repo = tmp_path / "r2"; repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "a.txt").write_text("1", encoding="utf-8"); _git(repo, "add", "."); _git(repo, "commit", "-qm", "c1")
    (repo / "a.txt").write_text("2", encoding="utf-8"); _git(repo, "add", "."); _git(repo, "commit", "-qm", "c2")
    _git(repo, "reset", "--hard", "HEAD~1")
    report = dcf.analyze(str(repo))
    assert any("reset" in r.lower() for r in report["reflog_rewrites"])


@needs_git
def test_cli_json_output(tmp_path):
    repo = tmp_path / "r3"; repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "a.txt").write_text("x", encoding="utf-8"); _git(repo, "add", "."); _git(repo, "commit", "-qm", "c")
    out = tmp_path / "report.json"
    assert dcf.main([str(repo), "--json", str(out)]) == 0
    import json
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["repo"] == str(repo) and "dangling_commits" in data


def test_nonexistent_path_no_crash(tmp_path):
    # a non-repo / missing path must not crash; report carries a note
    report = dcf.analyze(str(tmp_path / "does_not_exist"))
    assert report["dangling_count"] == 0
    assert isinstance(report["note"], str)


@needs_git
def test_regression_x1f_in_author_does_not_forge_date_subject(tmp_path):
    # [2] an attacker-controlled author name with \x1f separators must NOT shift the real date/subject
    repo = tmp_path / "evil"; repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "a.txt").write_text("x", encoding="utf-8")
    _git(repo, "add", ".")
    evil_author = "attacker\x1fdeadbeef\x1f2099-01-01T00:00:00+00:00"
    subprocess.run(["git", "-c", f"user.name={evil_author}", "-c", "user.email=a@a",
                    "-c", "commit.gpgsign=false", "-C", str(repo), "commit", "-qm", "REAL-SUBJECT"],
                   check=True, capture_output=True)
    sha = _rev(repo)
    meta = dcf.commit_meta(str(repo), sha)
    assert meta["subject"].startswith("REAL-SUBJECT")     # real subject not hidden
    assert meta["date"].startswith("20")                  # a real ISO date, not the forged token
    assert "deadbeef" not in meta["date"]


@needs_git
def test_regression_control_bytes_in_subject_neutralized(tmp_path):
    # [3] ANSI/newline in a commit subject must be escaped, not emitted verbatim
    repo = tmp_path / "ctl"; repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "a.txt").write_text("x", encoding="utf-8"); _git(repo, "add", ".")
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=a@a", "-c", "commit.gpgsign=false",
                    "-C", str(repo), "commit", "-qm", "evil\x1b[31m\ndropped"],
                   check=True, capture_output=True)
    meta = dcf.commit_meta(str(repo), _rev(repo))
    assert "\x1b" not in meta["subject"] and "\n" not in meta["subject"]
    assert "\\x1b" in meta["subject"]


def test_regression_clean_escapes_bidi_and_zerowidth():
    # [PR-3b second-pass] U+202E (RLO) / U+200B (ZWSP) / U+2028 (line sep) must be escaped, not emitted
    out = dcf._clean("a" + chr(0x202e) + "b" + chr(0x200b) + "c" + chr(0x2028) + "d" + chr(0x1b) + "e")
    for bad in (chr(0x202e), chr(0x200b), chr(0x2028), chr(0x1b)):
        assert bad not in out
    assert "\\u202e" in out and "\\u200b" in out and "\\x1b" in out
    assert dcf._clean("plain subject") == "plain subject"   # ASCII untouched


def test_uses_git_safe_hardening(monkeypatch, tmp_path):
    # the repo under investigation is UNTRUSTED: every git call must go through git_safe
    calls = []
    import safe_subprocess

    real = safe_subprocess.git_safe

    def spy(args, **kw):
        calls.append(args)
        return real(args, **kw)

    monkeypatch.setattr(dcf.safe_subprocess, "git_safe", spy)
    dcf.analyze(str(tmp_path))
    assert calls, "dangling_commit_finder must invoke git_safe (hardened), not raw git"
    assert all(a[0] == "-C" for a in calls)   # all run scoped to the target repo via -C
