"""Tests for private_tag.py - <private> boundary stripping."""
import sys
from pathlib import Path

_LIB = Path(__file__).resolve().parents[3] / "skills" / "coding-mastery" / "scripts" / "_lib"
sys.path.insert(0, str(_LIB))

import private_tag as pt  # noqa: E402


def test_strip_closed_span():
    clean, n = pt.strip_private("keep <private>drop me</private> keep")
    assert n == 1
    assert "drop me" not in clean
    assert clean == "keep [private omitted] keep"


def test_multiple_spans():
    clean, n = pt.strip_private("a <private>x</private> b <PRIVATE>y</PRIVATE> c")
    assert n == 2
    assert "x" not in clean and "y" not in clean


def test_multiline_span():
    clean, n = pt.strip_private("head\n<private>line1\nline2\nsecret</private>\ntail")
    assert n == 1
    assert "secret" not in clean and "line1" not in clean
    assert "head" in clean and "tail" in clean


def test_unclosed_tag_fails_closed_to_end():
    clean, n = pt.strip_private("safe prefix <private>sensitive tail with no close tag")
    assert n == 1
    assert "sensitive" not in clean
    assert clean == "safe prefix [private omitted]"


def test_stray_close_tag_removed():
    clean, n = pt.strip_private("text </private> more")
    assert "</private>" not in clean
    assert "text" in clean and "more" in clean


def test_none_stays_none_absent_not_redacted():
    clean, n = pt.strip_private(None)
    assert clean is None and n == 0


def test_empty_stays_empty():
    clean, n = pt.strip_private("")
    assert clean == "" and n == 0


def test_no_tag_passthrough():
    clean, n = pt.strip_private("nothing to strip here")
    assert clean == "nothing to strip here" and n == 0


def test_has_private():
    assert pt.has_private("a <private>b</private>")
    assert pt.has_private("a <private>b")          # unclosed still counts
    assert not pt.has_private("no tags")
    assert not pt.has_private(None)


def test_marker_is_value_free():
    # the marker must not encode the length or content of what it replaced
    clean, _ = pt.strip_private("<private>" + "X" * 5000 + "</private>")
    assert clean == pt.MARKER
    assert "5000" not in clean and "X" not in clean


# --------------------------------------------------------- CLI
def test_cli_strips_text(capsys):
    rc = pt.main(["--text", "a <private>b</private> c"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "b" not in out and "a" in out


def test_cli_check_exit_1_when_present(capsys):
    rc = pt.main(["--text", "x <private>y</private>", "--check"])
    assert rc == 1
    assert "present" in capsys.readouterr().out


def test_cli_check_exit_0_when_clean(capsys):
    rc = pt.main(["--text", "clean text", "--check"])
    assert rc == 0
    assert "no private content" in capsys.readouterr().out


def test_cli_file(tmp_path, capsys):
    f = tmp_path / "n.md"
    f.write_text("keep <private>drop</private>", encoding="utf-8")
    rc = pt.main(["--file", str(f)])
    assert rc == 0
    assert "drop" not in capsys.readouterr().out
