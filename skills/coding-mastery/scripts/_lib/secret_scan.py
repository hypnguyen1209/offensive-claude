#!/usr/bin/env python3
"""secret_scan.py - content-level credential detection + credentialed-URL redaction.

Two complements to redact_headers.py / http_creds.py (which mask KNOWN header names):
  1. scan(text)  - a secretlint-style catalog of credential regexes (AWS/GCP/GitHub/npm/
                   Slack/JWT/private-key/generic-high-entropy). Applied to ARBITRARY text
                   (fetched pages, subprocess output, a target we're about to pack). Every
                   Hit reports only {rule, line, col} - NEVER the matched value, so a scan
                   result can be logged without leaking the secret it found (CWE-532).
  2. redact_url / redact_error - port of repomix urlRedact.ts: strip `scheme://user:pw@host`
                   userinfo, scp-style `user@host`, and credential query params from any
                   string, so a git error echoing a credentialed remote URL is masked before
                   it reaches a log/report. ReDoS-bounded patterns (no catastrophic backtrack).

CLI:
  secret_scan.py --text "..."      # exit 1 if any secret found, 0 if clean, 2 on error
  secret_scan.py --file path       # scan a file
  secret_scan.py --redact "..."    # print the redacted string
"""
from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from typing import Optional

# ---------------------------------------------------------------- catalog
# (rule, compiled pattern). Patterns are anchored/bounded to avoid ReDoS.
_CATALOG: list[tuple[str, re.Pattern]] = [
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16}\b")),
    ("aws-secret-access-key", re.compile(r"\baws_secret_access_key\b\s*[=:]\s*['\"]?[A-Za-z0-9/+]{40}['\"]?", re.I)),
    ("gcp-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("github-token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[0-9A-Za-z_]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("npm-token", re.compile(r"\bnpm_[0-9A-Za-z]{36}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("private-key-block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("generic-secret-assignment", re.compile(
        r"\b(?:api[_-]?key|secret|passwd|password|token)\b\s*[=:]\s*['\"][^'\"\s]{8,}['\"]", re.I)),
]


@dataclass
class Hit:
    rule: str
    line: int
    col: int

    def to_dict(self) -> dict:
        return {"rule": self.rule, "line": self.line, "col": self.col}


def scan(text: Optional[str]) -> list[Hit]:
    """Return credential hits. Value-free: only rule + 1-based line/col."""
    if not text:
        return []
    hits: list[Hit] = []
    # precompute line-start offsets to map an absolute index -> (line, col)
    starts = [0]
    for m in re.finditer(r"\n", text):
        starts.append(m.end())

    def locate(idx: int) -> tuple[int, int]:
        lo, hi = 0, len(starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if starts[mid] <= idx:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1, idx - starts[lo] + 1

    for rule, pat in _CATALOG:
        for m in pat.finditer(text):
            line, col = locate(m.start())
            hits.append(Hit(rule, line, col))
    hits.sort(key=lambda h: (h.line, h.col, h.rule))
    return hits


# ---------------------------------------------------------------- redaction
_MAX_HOST = 255
# scheme://userinfo@host  -> mask userinfo (bounded userinfo, no catastrophic backtrack)
_URL_USERINFO = re.compile(r"([a-zA-Z][a-zA-Z0-9+.\-]*://)([^@/\s]{1,256})@")
# scp-style user[:pw]@host:path  (git@github.com:org/repo)
_SCP = re.compile(r"\b([A-Za-z0-9_.\-]{1,64})(?::[^@\s]{1,256})?@([A-Za-z0-9.\-]{1,%d})" % _MAX_HOST)
# credential query params
_QUERY_CRED = re.compile(
    r"([?&](?:access_token|api_key|apikey|token|password|passwd|secret|auth|sig|signature)=)"
    r"([^&\s#]{1,512})", re.I)

_MASK = "***"


def redact_url(text: Optional[str]) -> str:
    if not text:
        return text or ""
    out = _URL_USERINFO.sub(lambda m: f"{m.group(1)}{_MASK}@", text)
    out = _QUERY_CRED.sub(lambda m: f"{m.group(1)}{_MASK}", out)
    # scp-style: keep the host, drop any user/password
    out = _SCP.sub(lambda m: f"{_MASK}@{m.group(2)}" if ":" in m.group(0).split("@", 1)[0]
                   else m.group(0), out)
    return out


def redact_error(text: Optional[str]) -> str:
    """Redact any credentialed URL embedded in an error/log message."""
    return redact_url(text)


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Scan text for secrets / redact credentialed URLs.")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--text", help="scan this literal text")
    g.add_argument("--file", help="scan this file")
    g.add_argument("--redact", help="print the redacted form of this text")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    try:
        if args.redact is not None:
            print(redact_error(args.redact))
            return 0
        text = args.text
        if args.file:
            with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        hits = scan(text)
        if args.json:
            import json
            print(json.dumps([h.to_dict() for h in hits]))
        else:
            for h in hits:
                print(f"{h.line}:{h.col}: {h.rule}")  # value never printed
            if not hits:
                print("ok: no secrets detected")
        return 1 if hits else 0
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
