#!/usr/bin/env python3
"""redact_headers.py - strip secrets from HTTP headers/text before they reach the model.

When a proxy MCP (Burp/Caido) or any tool feeds captured traffic to the LLM, auth material
(Authorization, Cookie, Set-Cookie, API keys, tokens) must be masked at the DATA BOUNDARY
rather than relying on a prompt instruction not to echo it. Mechanical secret hygiene.

Fails CLOSED: detection does NOT hinge on an exhaustive allowlist. A header is redacted if
its name is a known/secret-looking name (heuristic, NFKC-folded) OR its value looks like a
secret (JWT, known token prefixes). Free-text redaction unfolds obs-fold continuations,
masks sensitive `key: value` / `"key":"value"` pairs, JWTs, bearer tokens, and known token
prefixes anywhere.

Use as a library:
    from redact_headers import redact_headers, redact_text
    safe = redact_headers(resp.headers)              # dict -> dict
    safe_dump = redact_text(raw_http)                # str  -> str
Or as a filter:
    cat request.txt | python redact_headers.py
"""
from __future__ import annotations

import re
import sys
import unicodedata

# explicit known-sensitive header names (exact match, in addition to the heuristic below)
SENSITIVE_HEADERS = frozenset(h.lower() for h in [
    "authorization", "proxy-authorization", "www-authenticate", "authentication",
    "cookie", "set-cookie", "x-api-key", "api-key", "apikey", "x-auth-token", "auth-token",
    "x-access-token", "x-csrf-token", "x-xsrf-token", "x-amz-security-token", "x-goog-api-key",
    "x-functions-key", "x-secret", "private-token", "x-vault-token",
])
# substrings that mark a header/field name as secret-bearing (fail-closed; over-masking is OK)
_NAME_HINTS = ("authorization", "auth", "token", "secret", "cookie", "session",
               "credential", "password", "passwd", "apikey", "api-key", "api_key",
               "signature", "bearer", "x-amz-security", "private-key", "client-secret")

# secret value signatures
_TOKEN_PREFIX = re.compile(
    r"(?i)\b(gh[pousr]_|glpat-|whsec_|sk-[a-z]*-?|pk_live_|rk_live_|AKIA|ASIA|xox[baprs]-|ya29\.|AIza|hf_|nvapi-)[A-Za-z0-9._-]{6,}")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+){0,2}")   # masks lone first segment too
_BEARER = re.compile(r"(?i)\b(Bearer|Basic|Token)\s+[A-Za-z0-9._~+/=-]{1,}")
# "key: value" / "key=value" / "key":"value" where key name looks secret
_KV_SECRET = re.compile(
    r'(?i)("?\b(?:access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|'
    r'api[_-]?key|secret|password|passwd|token|authorization|session|cookie|private[_-]?key|'
    r'signature)\b"?\s*[:=]\s*"?)([^"\s,&}\r\n]+)')
# a single header line (name : value); name is judged by heuristic in the callback
_HEADER_LINE = re.compile(r"(?im)^([ \t]*([A-Za-z0-9_!#$%&'*+.^`|~-]+)[ \t]*:[ \t]*)(.+?)[ \t]*$")


def _fold_name(name: str) -> str:
    return unicodedata.normalize("NFKC", name or "").encode("ascii", "ignore").decode("ascii").lower()


def _name_sensitive(name: str) -> bool:
    n = _fold_name(name)
    return n in SENSITIVE_HEADERS or any(h in n for h in _NAME_HINTS)


def _value_sensitive(value: str) -> bool:
    v = value or ""
    return bool(_TOKEN_PREFIX.search(v) or _JWT.search(v))


def mask_value(value: str) -> str:
    """Mask a secret, keeping a length-scaled hint (and any leading scheme like 'Bearer ')."""
    v = (value or "").strip()
    if not v:
        return ""
    scheme = ""
    parts = v.split(" ", 1)
    if len(parts) == 2 and parts[0].lower() in ("bearer", "basic", "digest", "token", "negotiate"):
        scheme, v = parts[0] + " ", parts[1]
    n = len(v)
    if n <= 8:
        return f"{scheme}***REDACTED***"
    if n <= 20:
        return f"{scheme}{v[:2]}***REDACTED***"          # short: at most 2 leading chars, no trailing
    return f"{scheme}{v[:3]}***REDACTED***{v[-2:]}"        # long: small hint both ends


def redact_headers(headers) -> dict:
    """Return a copy of a headers mapping with sensitive values masked (name- or value-based)."""
    try:
        items = headers.items()
    except AttributeError:
        items = list(headers)
    out = {}
    for k, v in items:
        sv = str(v)
        out[k] = mask_value(sv) if (_name_sensitive(str(k)) or _value_sensitive(sv)) else v
    return out


def _unfold(text: str) -> str:
    """Join obs-fold header continuations (a line starting with SP/HTAB) onto the prior line."""
    return re.sub(r"\r?\n[ \t]+", " ", text)


def redact_text(text: str) -> str:
    """Redact sensitive header lines + secret kv-pairs + JWT/bearer/token-prefix runs."""
    out = _unfold(text)

    def _hdr(m):
        return f"{m.group(1)}{mask_value(m.group(3))}" if _name_sensitive(m.group(2)) else m.group(0)

    out = _HEADER_LINE.sub(_hdr, out)
    out = _KV_SECRET.sub(lambda m: f"{m.group(1)}***REDACTED***", out)
    out = _TOKEN_PREFIX.sub("***REDACTED-TOKEN***", out)
    out = _JWT.sub("eyJ***REDACTED-JWT***", out)
    out = _BEARER.sub(lambda m: f"{m.group(1)} ***REDACTED***", out)
    return out


def main(argv=None) -> int:
    sys.stdout.write(redact_text(sys.stdin.read()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
