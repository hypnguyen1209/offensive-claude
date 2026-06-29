"""Tests for redact_headers - secrets must not survive redaction."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "skills" / "coding-mastery" / "scripts" / "_lib"))

import pytest  # noqa: E402
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


# ========================================================= adversarial regressions
@pytest.mark.parametrize("name,secret", [
    ("X-Session-Token", "s3cr3tSessionValue1234567890"),
    ("Authorization2", "Bearer abcdefghijklmnopqrstuvwxyz0123"),
    ("X-Refresh-Token", "rt_live_abcdef1234567890SECRET"),
    ("X-Gitlab-Token", "glpat-XYZ123456789secretAAAA"),
    ("Stripe-Signature", "whsec_abcdef0123456789secretZZ"),
])
def test_regression_secretish_header_names_masked(name, secret):
    out = rh.redact_headers({name: secret})
    assert secret not in out[name]


def test_regression_value_backstop_unknown_name():
    # name not sensitive, but value is a known token prefix -> still masked
    out = rh.redact_headers({"X-Custom-Thing": "ghp_abcdefghij0123456789klmnopqrstuvwx"})
    assert "ghp_abcdefghij0123456789klmnopqrstuvwx" not in out["X-Custom-Thing"]


def test_regression_obsfold_continuation_masked():
    raw = ("GET / HTTP/1.1\r\n"
           "Authorization: Bearer firstpart\r\n"
           " CONTINUATIONSECRET12345\r\n"
           "Host: acme.com\r\n\r\n")
    out = rh.redact_text(raw)
    assert "CONTINUATIONSECRET12345" not in out


def test_regression_lone_jwt_segment_masked():
    seg = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"   # base64 of {"alg":"HS256","typ":"JWT"}
    out = rh.redact_text(f"leaked header segment: {seg} end")
    assert seg not in out


def test_regression_json_access_token_masked():
    secret = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5"
    out = rh.redact_text(f'{{"access_token": "{secret}", "expires_in": 3600}}')
    assert secret not in out


def test_regression_homoglyph_header_name_masked():
    # Greek omicron (U+03BF) in "Authorizati0n"
    name = "Authorizatiοn"
    out = rh.redact_headers({name: "unicodesecret_value_123456"})
    assert "unicodesecret_value_123456" not in out[name]


def test_regression_short_bearer_masked():
    out = rh.redact_text("data Bearer short12 end")
    assert "short12" not in out


def test_regression_short_secret_not_half_revealed():
    # old behavior leaked 'abcd***fg'; now a short secret reveals neither end
    m = rh.mask_value("abcdefg")
    assert "abcdefg" not in m and "abcd" not in m and "fg" not in m
