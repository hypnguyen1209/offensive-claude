"""Tests for secret_scan — content-level credential detection + credentialed-URL redaction.

Ports repomix's secretlint catalog concept + urlRedact.ts (CWE-532). The scanner must
find credentials in arbitrary text and, crucially, NEVER include the matched secret VALUE
in its output (only rule name + line/col). Redaction must mask credentials in URLs and
error strings while preserving surrounding text.

Run: pytest tests/scripts/coding-mastery/test_secret_scan.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "skills" / "coding-mastery" / "scripts" / "_lib"))

import pytest  # noqa: E402
import secret_scan as ss  # noqa: E402


# ------------------------------------------------------------------ detection
@pytest.mark.parametrize("text,rule_substr", [
    ("aws_key = AKIAIOSFODNN7EXAMPLE", "aws"),
    ("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "github"),
    ("-----BEGIN RSA PRIVATE KEY-----", "private-key"),
    ("token: xoxb" + "-123456789012-abcdefghijklmnop", "slack"),
])
def test_detects_known_secret(text, rule_substr):
    hits = ss.scan(text)
    assert hits, f"expected a hit in {text!r}"
    assert any(rule_substr in h.rule for h in hits)


def test_clean_text_no_hits():
    assert ss.scan("def add(a, b):\n    return a + b\n") == []


def test_hit_never_contains_the_value():
    secret = "AKIAIOSFODNN7EXAMPLE"
    hits = ss.scan(f"key={secret}")
    assert hits
    for h in hits:
        # neither the repr nor any attribute may carry the raw secret
        assert secret not in repr(h)
        assert secret not in str(h.to_dict())


def test_hit_reports_line_and_col():
    hits = ss.scan("line1\nAKIAIOSFODNN7EXAMPLE\n")
    assert hits and hits[0].line == 2


# ------------------------------------------------------------------ url redaction
def test_redact_url_userinfo():
    out = ss.redact_url("https://user:s3cr3t@example.com/path")
    assert "s3cr3t" not in out
    assert "example.com/path" in out


def test_redact_scp_style():
    out = ss.redact_url("git@github.com:org/repo.git")
    assert "github.com" in out  # host preserved, no crash


def test_redact_credential_query_param():
    out = ss.redact_url("https://api.example.com/x?access_token=abcdef123&y=1")
    assert "abcdef123" not in out
    assert "y=1" in out


def test_redact_error_masks_embedded_url():
    msg = "fatal: could not read from https://alice:pw123@git.example.com/repo"
    out = ss.redact_error(msg)
    assert "pw123" not in out
    assert "fatal: could not read" in out


def test_redact_is_redos_bounded():
    # a pathological host must return quickly, not hang (bounded regex)
    ss.redact_url("https://" + "a" * 10000 + "@h/")


# ------------------------------------------------------------------ CLI
def test_cli_exit_codes():
    assert ss.main(["--text", "AKIAIOSFODNN7EXAMPLE"]) == 1   # found -> nonzero
    assert ss.main(["--text", "hello world"]) == 0            # clean
