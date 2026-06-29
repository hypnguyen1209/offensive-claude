#!/usr/bin/env python3
"""http_creds.py — build auth headers from the environment without leaking tokens.

Stops every script from re-implementing os.getenv + header assembly, and makes the
secret SAFE TO LOG: repr/str are masked, so an accidental print(cred) or logging of a
call never dumps the token.

Secrets live in the ENVIRONMENT (or your shell secret manager / age / keyring) — this
helper deliberately does NOT read or write a plaintext credential file.

Usage:
    from http_creds import Cred
    cred = Cred.from_env("ACME_TOKEN", scheme="bearer")          # reads $ACME_TOKEN
    requests.get(url, headers=cred.as_headers())
    print(cred)            # -> <Cred bearer Authorization=eyJ***9Q>   (masked)

Schemes: bearer | api_key | cookie | basic
"""
from __future__ import annotations

import base64
import os
from typing import Optional


def mask(secret: str, show_start: int = 3, show_end: int = 2) -> str:
    """Mask a secret for logs: keep a few chars at each end, star the middle."""
    if secret is None:
        return ""
    if len(secret) <= show_start + show_end:
        return "*" * len(secret)
    return f"{secret[:show_start]}***{secret[-show_end:]}"


class Cred:
    __slots__ = ("_token", "scheme", "header_name", "username", "cookie_name")

    def __init__(self, token: str, scheme: str = "bearer", *, header_name: Optional[str] = None,
                 username: Optional[str] = None, cookie_name: str = "session"):
        if not token:
            raise ValueError("empty credential")
        scheme = scheme.lower()
        if scheme not in ("bearer", "api_key", "cookie", "basic"):
            raise ValueError(f"unknown scheme: {scheme}")
        self._token = token
        self.scheme = scheme
        self.header_name = header_name or "X-API-Key"
        self.username = username
        self.cookie_name = cookie_name

    @classmethod
    def from_env(cls, var: str, scheme: str = "bearer", *, required: bool = True, **kw) -> Optional["Cred"]:
        val = os.environ.get(var)
        if not val:
            if required:
                raise KeyError(f"environment variable {var} is not set")
            return None
        return cls(val, scheme, **kw)

    def as_headers(self) -> dict:
        if self.scheme == "bearer":
            return {"Authorization": f"Bearer {self._token}"}
        if self.scheme == "api_key":
            return {self.header_name: self._token}
        if self.scheme == "cookie":
            return {"Cookie": f"{self.cookie_name}={self._token}"}
        if self.scheme == "basic":
            raw = f"{self.username or ''}:{self._token}".encode("utf-8")
            return {"Authorization": "Basic " + base64.b64encode(raw).decode("ascii")}
        raise ValueError(self.scheme)  # pragma: no cover

    # --- safe logging: never expose the raw token ---
    def __repr__(self) -> str:
        return f"<Cred {self.scheme} {self.header_name if self.scheme == 'api_key' else 'token'}={mask(self._token)}>"

    __str__ = __repr__
