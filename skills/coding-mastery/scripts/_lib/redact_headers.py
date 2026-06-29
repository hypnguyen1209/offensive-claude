#!/usr/bin/env python3
"""redact_headers.py - strip secrets from HTTP headers/text before they reach the model.

When a proxy MCP (Burp/Caido) or any tool feeds captured traffic to the LLM, auth material
(Authorization, Cookie, Set-Cookie, API keys, tokens) should be masked at the DATA BOUNDARY
rather than relying on a prompt instruction not to echo it. Mechanical secret hygiene.

Use as a library:
    from redact_headers import redact_headers, redact_text
    safe = redact_headers(resp.headers)              # dict -> dict
    safe_dump = redact_text(raw_http)                # str  -> str

Or as a filter:
    cat request.txt | python redact_headers.py       # redacts sensitive header lines on stdin
"""
from __future__ import annotations

import re
import sys

# header names whose VALUE must never reach the model verbatim
SENSITIVE_HEADERS = frozenset(h.lower() for h in [
    "authorization", "proxy-authorization", "www-authenticate", "authentication",
    "cookie", "set-cookie",
    "x-api-key", "api-key", "apikey", "x-auth-token", "auth-token", "x-access-token",
    "x-csrf-token", "x-xsrf-token", "x-amz-security-token", "x-goog-api-key",
    "x-functions-key", "x-secret", "private-token", "x-vault-token",
])

_KEEP_START, _KEEP_END = 4, 2


def mask_value(value: str) -> str:
    """Mask a secret, keeping a tiny hint (and any leading scheme like 'Bearer ')."""
    v = (value or "").strip()
    if not v:
        return ""
    scheme = ""
    parts = v.split(" ", 1)
    if len(parts) == 2 and parts[0].lower() in ("bearer", "basic", "digest", "token", "negotiate"):
        scheme = parts[0] + " "
        v = parts[1]
    if len(v) <= _KEEP_START + _KEEP_END:
        return f"{scheme}***REDACTED***"
    return f"{scheme}{v[:_KEEP_START]}***REDACTED***{v[-_KEEP_END:]}"


def redact_headers(headers) -> dict:
    """Return a copy of a headers mapping with sensitive values masked (case-insensitive)."""
    try:
        items = headers.items()
    except AttributeError:
        items = list(headers)
    out = {}
    for k, v in items:
        out[k] = mask_value(str(v)) if str(k).lower() in SENSITIVE_HEADERS else v
    return out


# raw-text redaction: a "Header-Name: value" line whose name is sensitive
_HEADER_LINE = re.compile(
    r"(?im)^([ \t]*(" + "|".join(re.escape(h) for h in sorted(SENSITIVE_HEADERS)) + r"))[ \t]*:[ \t]*(.+?)[ \t]*$")
# stray bearer tokens / JWTs anywhere in free text
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}")


def redact_text(text: str) -> str:
    """Redact sensitive header lines + stray bearer/JWT tokens in raw HTTP/text."""
    def _hdr(m):
        return f"{m.group(1)}: {mask_value(m.group(3))}"
    out = _HEADER_LINE.sub(_hdr, text)
    out = _BEARER.sub("Bearer ***REDACTED***", out)
    out = _JWT.sub("eyJ***REDACTED-JWT***", out)
    return out


def main(argv=None) -> int:
    data = sys.stdin.read()
    sys.stdout.write(redact_text(data))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
