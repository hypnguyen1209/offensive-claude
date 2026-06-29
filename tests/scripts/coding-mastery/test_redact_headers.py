"""Tests for redact_headers - secrets must not survive redaction."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "skills" / "coding-mastery" / "scripts" / "_lib"))

import redact_headers as rh  # noqa: E402

TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.s1gnatureZZ"


def test_authorization_masked():
    h = rh.redact_headers({"Authorization": f"Bearer {TOKEN}", "Accept": "application/json"})
    assert TOKEN not in h["Authorization"]
    assert h["Authorization"].startswith("Bearer ")
    assert h["Accept"] == "application/json"          # non-sensitive untouched


def test_cookie_and_setcookie_masked():
    h = rh.redact_headers({"Cookie": "session=supersecretvalue123", "Set-Cookie": "id=abcdef123456; HttpOnly"})
    assert "supersecretvalue123" not in h["Cookie"]
    assert "abcdef123456" not in h["Set-Cookie"]


def test_case_insensitive_header_name():
    h = rh.redact_headers({"x-API-Key": "k1234567890abcdef"})
    assert "k1234567890abcdef" not in h["x-API-Key"]


def test_short_value_fully_redacted():
    h = rh.redact_headers({"X-Api-Key": "abc"})
    assert "abc" not in h["X-Api-Key"]


def test_redact_text_header_lines():
    raw = ("GET /a HTTP/1.1\r\n"
           "Host: api.acme.com\r\n"
           f"Authorization: Bearer {TOKEN}\r\n"
           "Cookie: session=topsecretsession\r\n"
           "Accept: */*\r\n\r\n")
    out = rh.redact_text(raw)
    assert TOKEN not in out
    assert "topsecretsession" not in out
    assert "Host: api.acme.com" in out               # non-sensitive preserved


def test_redact_text_stray_jwt_and_bearer():
    out = rh.redact_text(f"the response body leaked {TOKEN} and Bearer {TOKEN} inline")
    assert TOKEN not in out
    assert "REDACTED" in out


def test_cli_filter(capsys):
    import io
    sys.stdin = io.StringIO(f"Authorization: Bearer {TOKEN}\n")
    try:
        assert rh.main() == 0
    finally:
        sys.stdin = sys.__stdin__
    assert TOKEN not in capsys.readouterr().out
