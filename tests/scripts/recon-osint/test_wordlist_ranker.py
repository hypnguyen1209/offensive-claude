"""Tests for wordlist_ranker - frequency tiering for spray prep."""
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "skills" / "recon-osint" / "scripts"))

import wordlist_ranker as wr  # noqa: E402


import pytest  # noqa: E402


@pytest.mark.parametrize("count,tier", [
    (None, "org-specific"), (0, "org-specific"),
    (1, "sweet-spot"), (1000, "sweet-spot"),
    (1001, "common"), (1_000_000, "common"),
    (1_000_001, "generic"), (50_000_000, "generic"),
])
def test_tier_for(count, tier):
    assert wr.tier_for(count) == tier


def test_lookup_plaintext_and_sha1():
    word = "Spring2026!"
    sha1 = hashlib.sha1(word.encode()).hexdigest().upper()
    assert wr.lookup_count(word, {word.lower(): 42}) == 42
    assert wr.lookup_count(word, {sha1: 7}) == 7
    assert wr.lookup_count(word, {}) is None


def test_rank_orders_org_specific_first():
    counts = {"password": 9_999_999, "summer2026": 5}
    ranked = wr.rank(["password", "summer2026", "Acme!Internal"], counts)
    assert ranked[0]["word"] == "Acme!Internal" and ranked[0]["tier"] == "org-specific"
    assert ranked[-1]["word"] == "password" and ranked[-1]["tier"] == "generic"


def test_load_counts(tmp_path):
    f = tmp_path / "c.txt"
    f.write_text("password:9999999\nSummer2026 5\nGARBAGE\n" + "A" * 40 + ":3\n", encoding="utf-8")
    counts = wr.load_counts(str(f))
    assert counts["password"] == 9999999
    assert counts["summer2026"] == 5
    assert counts["A" * 40] == 3            # sha1-like key kept uppercase


def test_cli_spray_filter(tmp_path, capsys):
    wl = tmp_path / "w.txt"; wl.write_text("password\nsummer2026\nAcmeOrg2026\n", encoding="utf-8")
    cf = tmp_path / "c.txt"; cf.write_text("password:9999999\nsummer2026:5\n", encoding="utf-8")
    assert wr.main(["--wordlist", str(wl), "--counts", str(cf), "--tier", "spray"]) == 0
    out = capsys.readouterr().out
    assert "password" not in out             # generic filtered out
    assert "summer2026" in out and "AcmeOrg2026" in out
