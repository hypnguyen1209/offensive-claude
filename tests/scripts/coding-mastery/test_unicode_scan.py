"""Tests for unicode_scan — invisible/bidi/ASCII-smuggling codepoint defense.

Ports ecc check-unicode-safety.js taxonomy. Detects prompt-injection smuggling vectors in
untrusted content (proxy traffic, fetched pages) before it enters context or a report, and
can strip them. A security-relevant defense for our untrusted-content threat model.

Run: pytest tests/scripts/coding-mastery/test_unicode_scan.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "skills" / "coding-mastery" / "scripts" / "_lib"))

import pytest  # noqa: E402
import unicode_scan as us  # noqa: E402


@pytest.mark.parametrize("bad", [
    "hello​world",          # zero-width space
    "a‎ b",                 # LTR mark
    "x‮reversed",           # RLO bidi override
    "tag\U000e0041smuggle",      # Unicode Tag block (ASCII smuggling)
    "math⁤invisible",       # invisible plus
    "﻿bom-lead",            # zero-width no-break space / BOM mid-text
])
def test_detects_dangerous(bad):
    hits = us.scan(bad)
    assert hits, f"expected a hit in {bad!r}"


def test_plain_ascii_clean():
    assert us.scan("normal text, 123, symbols !@#$.") == []


def test_normal_unicode_allowed():
    # accented letters and CJK are legitimate content, not smuggling
    assert us.scan("café résumé 日本語 emoji 🙂") == []


def test_strip_removes_invisible():
    dirty = "secret​‮payload\U000e0041"
    clean = us.strip(dirty)
    assert us.scan(clean) == []
    assert "secret" in clean and "payload" in clean


def test_hit_reports_codepoint_and_position():
    hits = us.scan("a​b")
    assert hits[0].index == 1
    assert "200b" in hits[0].codepoint.lower()


def test_cli_detects(tmp_path):
    f = tmp_path / "x.txt"
    f.write_text("clean​dirty", encoding="utf-8")
    assert us.main(["--file", str(f)]) == 1        # found
    # --write strips and rewrites -> subsequent scan clean
    assert us.main(["--file", str(f), "--write"]) == 0
    assert us.scan(f.read_text(encoding="utf-8")) == []
