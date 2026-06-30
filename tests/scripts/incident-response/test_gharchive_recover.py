"""Tests for gharchive_recover - recovery query/URL builder (offline, pure stdlib).

Run: pytest tests/scripts/incident-response/test_gharchive_recover.py
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "skills" / "incident-response" / "scripts"))

import pytest  # noqa: E402
import gharchive_recover as gr  # noqa: E402


def test_events_url():
    assert gr.github_events_url("aws/aws-toolkit-vscode").startswith(
        "https://api.github.com/repos/aws/aws-toolkit-vscode/events")


def test_wayback_queries_cover_pulls_issues_commits():
    q = gr.wayback_cdx_urls("o/r")
    assert "github.com/o/r/pull" in q["pulls"]
    assert "github.com/o/r/issues" in q["issues"]
    assert "web.archive.org/cdx" in q["commits"]


def test_repo_validation():
    for bad in ("nothaslash", "o/r/extra", "../etc", "o /r"):
        with pytest.raises(ValueError):
            gr.recovery_plan(bad)


def test_gharchive_hours_count():
    urls = gr.gharchive_http_hours("2026-06-01", "2026-06-01")
    assert len(urls) == 24
    assert urls[0] == "https://data.gharchive.org/2026-06-01-0.json.gz"
    assert urls[-1].endswith("2026-06-01-23.json.gz")


def test_gharchive_range_two_days():
    assert len(gr.gharchive_http_hours("2026-06-01", "2026-06-02")) == 48


def test_gharchive_rejects_inverted_and_huge_range():
    with pytest.raises(ValueError):
        gr.gharchive_http_hours("2026-06-10", "2026-06-01")
    with pytest.raises(ValueError):
        gr.gharchive_http_hours("2026-01-01", "2026-12-31")   # > 31 days


def test_gharchive_bad_date():
    with pytest.raises(ValueError):
        gr.gharchive_http_hours("06/01/2026", "2026-06-02")


def test_bigquery_sql_is_optional_and_well_formed():
    sql = gr.gharchive_bigquery_sql("o/r", "2026-06-01", "2026-06-30")
    assert "OPTIONAL" in sql and "githubarchive.day.*" in sql
    assert "_TABLE_SUFFIX BETWEEN '20260601' AND '20260630'" in sql
    assert "repo.name = 'o/r'" in sql


def test_recovery_plan_shape():
    plan = gr.recovery_plan("o/r", "2026-06-01", "2026-06-02")
    assert plan["repo"] == "o/r"
    assert "github_events_api" in plan["sources"]
    assert plan["sources"]["gharchive_http"]["files"]   # populated when dates given
    assert "bigquery" in str(plan["optional"]).lower()
    assert "dangling_commit_finder" in plan["also_run"]


def test_recovery_plan_without_dates_omits_files():
    plan = gr.recovery_plan("o/r")
    assert "files" not in plan["sources"]["gharchive_http"]


def test_cli_plan(tmp_path):
    out = tmp_path / "plan.json"
    assert gr.main(["plan", "o/r", "--json", str(out)]) == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["repo"] == "o/r"


def test_cli_bad_repo():
    assert gr.main(["plan", "notarepo"]) == 2


# --------- PR-3b red-team regressions (raptor wjg32ea1y) ---------
def test_regression_trailing_newline_repo_rejected():
    # [4] re.match+$ accepted 'o/r\n' (CRLF injection into URLs); fullmatch must reject it
    for bad in ("o/r\n", "o\nr", "o/r\r\nHost: evil", "o/r "):
        with pytest.raises(ValueError):
            gr.recovery_plan(bad)


def test_regression_bigquery_validates_dates_on_direct_call():
    # [5] gharchive_bigquery_sql must validate its own dates, not trust the caller
    with pytest.raises(ValueError):
        gr.gharchive_bigquery_sql("o/r", "2026-06-01'; DROP TABLE x;--", "2026-06-30")
    with pytest.raises(ValueError):
        gr.gharchive_bigquery_sql("o/r", "not-a-date", "2026-06-30")


# --------- PR-3b second-pass regressions (raptor wt0d3jbeb) ---------
def test_regression_unicode_digit_date_rejected():
    # [4] a fullwidth-digit date passed \d but got interpolated raw; [0-9] must reject it
    fullwidth = "２０２６-06-01"   # '２０２６-06-01'
    with pytest.raises(ValueError):
        gr._check_date(fullwidth)
    with pytest.raises(ValueError):
        gr.gharchive_bigquery_sql("o/r", fullwidth, "2026-06-30")


def test_regression_bigquery_uses_normalized_suffix():
    # the SQL must carry the NORMALIZED date, never the raw input string
    sql = gr.gharchive_bigquery_sql("o/r", "2026-06-01", "2026-06-30")
    assert "_TABLE_SUFFIX BETWEEN '20260601' AND '20260630'" in sql
