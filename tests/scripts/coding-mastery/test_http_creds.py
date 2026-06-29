"""Tests for http_creds — header assembly + token masking (no leakage)."""
import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "skills" / "coding-mastery" / "scripts" / "_lib"))

import pytest  # noqa: E402
import http_creds as hc  # noqa: E402

SECRET = "eyJhbGciOiJIUzI1NiJ9.payload.signature9Q"


def test_bearer_header():
    assert hc.Cred(SECRET, "bearer").as_headers() == {"Authorization": f"Bearer {SECRET}"}


def test_api_key_header_custom_name():
    h = hc.Cred(SECRET, "api_key", header_name="X-Acme-Key").as_headers()
    assert h == {"X-Acme-Key": SECRET}


def test_cookie_header():
    h = hc.Cred("abc", "cookie", cookie_name="sid").as_headers()
    assert h == {"Cookie": "sid=abc"}


def test_basic_header():
    h = hc.Cred("pw", "basic", username="user").as_headers()
    assert h == {"Authorization": "Basic " + base64.b64encode(b"user:pw").decode()}


def test_repr_masks_secret():
    c = hc.Cred(SECRET, "bearer")
    r = repr(c)
    assert SECRET not in r and "***" in r and str(c) == r


def test_short_secret_fully_masked():
    assert hc.mask("abcd") == "****"
    assert "shh" not in hc.mask("shh")


def test_from_env(monkeypatch):
    monkeypatch.setenv("ACME_TOKEN", SECRET)
    c = hc.Cred.from_env("ACME_TOKEN", "bearer")
    assert c.as_headers()["Authorization"] == f"Bearer {SECRET}"


def test_from_env_missing_required(monkeypatch):
    monkeypatch.delenv("NOPE_TOKEN", raising=False)
    with pytest.raises(KeyError):
        hc.Cred.from_env("NOPE_TOKEN")


def test_from_env_missing_optional(monkeypatch):
    monkeypatch.delenv("NOPE_TOKEN", raising=False)
    assert hc.Cred.from_env("NOPE_TOKEN", required=False) is None


def test_empty_token_rejected():
    with pytest.raises(ValueError):
        hc.Cred("", "bearer")


def test_unknown_scheme_rejected():
    with pytest.raises(ValueError):
        hc.Cred("x", "magic")
