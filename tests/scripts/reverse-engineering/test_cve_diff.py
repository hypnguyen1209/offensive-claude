"""Tests for cve_diff - multi-source fix-commit discovery (offline) + scope-gated diff.

Run: pytest tests/scripts/reverse-engineering/test_cve_diff.py
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "skills" / "reverse-engineering" / "scripts"))

import pytest  # noqa: E402
import cve_diff as cd  # noqa: E402

SHA = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"


# --------------------------------------------------------- URL parsing
def test_parse_github_commit():
    pc = cd.parse_commit_url(f"https://github.com/openssl/openssl/commit/{SHA}")
    assert pc["repo"] == "openssl/openssl" and pc["sha"] == SHA and pc["host"] == "github.com"


def test_parse_gitlab_commit():
    pc = cd.parse_commit_url(f"https://gitlab.com/grp/sub/proj/-/commit/{SHA}")
    assert pc["sha"] == SHA and "grp/sub/proj" in pc["repo"]


def test_parse_cgit_commit():
    pc = cd.parse_commit_url("https://git.kernel.org/pub/scm/linux.git/?id=" + SHA)
    assert pc["sha"] == SHA and pc["host"] == "git.kernel.org"


def test_parse_non_commit_url_is_none():
    assert cd.parse_commit_url("https://example.com/advisory/123") is None
    assert cd.parse_commit_url(12345) is None


# --------------------------------------------------------- extraction
def test_extract_from_osv_references_and_ranges():
    osv = {
        "id": "CVE-2024-0001",
        "references": [{"type": "FIX", "url": f"https://github.com/o/r/commit/{SHA}"}],
        "affected": [{"ranges": [{"type": "GIT", "repo": "https://github.com/o/r",
                                  "events": [{"introduced": "0"}, {"fixed": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}]}]}],
    }
    fcs = cd.extract_fix_commits(osv, source="osv")
    shas = {f["sha"] for f in fcs}
    assert SHA in shas and "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef" in shas


def test_extract_from_nvd_shape():
    nvd = {"vulnerabilities": [{"cve": {"references": [
        {"url": f"https://github.com/o/r/commit/{SHA}", "tags": ["Patch"]}]}}]}
    fcs = cd.extract_fix_commits(nvd, source="nvd")
    assert any(f["sha"] == SHA for f in fcs)


def test_extract_ignores_non_git_ranges():
    osv = {"affected": [{"ranges": [{"type": "SEMVER", "events": [{"fixed": "1.2.3"}]}]}]}
    assert cd.extract_fix_commits(osv) == []


# --------------------------------------------------------- discover (injectable fetcher)
def test_discover_merges_and_dedupes():
    url = f"https://github.com/o/r/commit/{SHA}"
    def fetcher(u):
        if "osv.dev" in u:
            return {"references": [{"url": url}]}
        if "nvd" in u:
            return {"vulnerabilities": [{"cve": {"references": [{"url": url}]}}]}
        return {}
    res = cd.discover("CVE-2024-0001", sources=("osv", "nvd"), fetcher=fetcher)
    assert res["count"] == 1                         # same (repo, sha) deduped across sources
    assert "nvd" in res["fix_commits"][0].get("also_in", [])
    assert set(res["queried"]) == {"osv", "nvd"}


def test_discover_records_source_error_not_fatal():
    def fetcher(u):
        if "osv.dev" in u:
            raise RuntimeError("network down")
        return {"references": [{"url": f"https://github.com/o/r/commit/{SHA}"}]}
    res = cd.discover("CVE-2024-0001", sources=("osv", "ghsa"), fetcher=fetcher)
    assert "osv" in res["errors"] and res["count"] == 1   # ghsa still contributed


def test_discover_rejects_bad_cve():
    with pytest.raises(ValueError):
        cd.discover("not-a-cve", fetcher=lambda u: {})


# --------------------------------------------------------- scope-gated diff
def _scope(tmp_path, in_scope):
    p = tmp_path / "scope.json"
    p.write_text(json.dumps({"engagement": "t", "in_scope": in_scope}), encoding="utf-8")
    return str(p)


class _Res:
    def __init__(self, rc=0, out="", err=""):
        self.returncode, self.stdout, self.stderr = rc, out, err


def test_diff_refuses_out_of_scope(tmp_path):
    scope = _scope(tmp_path, ["github.com"])
    calls = []
    res = cd.fetch_diff("https://evil.example/o/r", SHA, scope,
                        runner=lambda args: calls.append(args) or _Res())
    assert res["in_scope"] is False and "out of scope" in res["error"]
    assert calls == []                               # never cloned an out-of-scope repo


def test_diff_in_scope_runs_clone_and_diff(tmp_path):
    scope = _scope(tmp_path, ["github.com"])
    seen = []
    def runner(args):
        seen.append(args)
        if "diff" in args:
            return _Res(out="--- a\n+++ b\n@@ -1 +1 @@\n-bad\n+good\n")
        return _Res()
    res = cd.fetch_diff("https://github.com/o/r", SHA, scope, workdir=str(tmp_path / "wd"), runner=runner)
    assert res["in_scope"] is True and "+good" in res["diff"]
    assert any("clone" in a for a in seen) and any("diff" in a for a in seen)   # cloned then diffed


def test_diff_clone_failure_reported(tmp_path):
    scope = _scope(tmp_path, ["github.com"])
    res = cd.fetch_diff("https://github.com/o/r", SHA, scope, workdir=str(tmp_path / "wd"),
                        runner=lambda args: _Res(rc=128, err="fatal: repository not found"))
    assert res["in_scope"] is True and "clone failed" in res["error"]


# --------------------------------------------------------- CLI
def test_cli_find_offline(tmp_path, monkeypatch):
    monkeypatch.setattr(cd, "_http_get", lambda u, timeout=20:
                        {"references": [{"url": f"https://github.com/o/r/commit/{SHA}"}]} if "osv" in u else {})
    out = tmp_path / "f.json"
    assert cd.main(["find", "CVE-2024-0001", "--source", "osv", "--json", str(out)]) == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["count"] == 1


def test_cli_find_bad_cve():
    assert cd.main(["find", "nope"]) == 2
