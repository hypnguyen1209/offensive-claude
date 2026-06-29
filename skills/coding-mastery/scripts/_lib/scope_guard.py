#!/usr/bin/env python3
"""scope_guard.py — executable engagement-scope enforcement.

Turns the prose ROE / scope-definition into a machine-readable allowlist that every
active script can consult before it touches a target. Errs SAFE: anything not provably
in-scope is treated as out-of-scope, and out-of-scope rules always win over in-scope.

Pure stdlib, cross-platform (no fcntl/POSIX-only deps).

Scope file (JSON), see templates/scope/scope.schema.json:
  {
    "engagement": "ACME-2026-Q2",
    "in_scope":     ["acme.com", "*.acme.com", "203.0.113.0/24", "198.51.100.7",
                     "https://api.acme.com"],
    "out_of_scope": ["dev.acme.com", "*.internal.acme.com", "203.0.113.13"],
    "max_cidr_hosts": 1024
  }

Wildcard semantics (deliberately strict for safety):
  "*.acme.com"  matches ONLY sub-domains (a.acme.com, x.y.acme.com).
                It does NOT match the apex "acme.com" — list the apex separately.
                It does NOT match look-alikes ("evil-acme.com", "acme.com.evil.com").

CLI:
  scope_guard.py check  <target> --scope scope.json     # exit 0=in-scope, 3=out, 2=error
  scope_guard.py classify <value>                        # print the parsed kind
  scope_guard.py expand <cidr> [--max N]                 # list hosts (capped)
Use --json for machine-readable output.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from dataclasses import dataclass, asdict
from typing import Optional
from urllib.parse import urlsplit

DEFAULT_MAX_CIDR_HOSTS = 1024


class ScopeError(Exception):
    """Malformed scope file or target."""


# --------------------------------------------------------------------------- parsing
def _strip_host(value: str) -> str:
    """Lowercase, strip a single trailing dot and surrounding whitespace."""
    h = value.strip().lower()
    if h.endswith(".") and not h.endswith(".."):
        h = h[:-1]
    return h


def split_host_port(value: str) -> tuple[str, Optional[int]]:
    """Return (host, port) from a host, host:port, [v6], [v6]:port, or URL string."""
    v = value.strip()
    if "://" in v:
        parts = urlsplit(v)
        host = parts.hostname or ""
        return _strip_host(host), parts.port
    # bracketed IPv6 literal, optionally with :port
    if v.startswith("["):
        end = v.find("]")
        if end != -1:
            host = v[1:end]
            rest = v[end + 1:]
            port = int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else None
            return _strip_host(host), port
    # bare IPv6 (more than one colon, no brackets) -> no port
    if v.count(":") > 1:
        return _strip_host(v), None
    if ":" in v:
        host, _, p = v.rpartition(":")
        return _strip_host(host), (int(p) if p.isdigit() else None)
    return _strip_host(v), None


def classify(value: str) -> str:
    """Classify a scope rule or target string: url|cidr|ip|wildcard|domain|invalid."""
    v = value.strip()
    if not v:
        return "invalid"
    if "://" in v:
        return "url"
    if v.startswith("*."):
        base = _strip_host(v[2:])
        return "wildcard" if _is_domain(base) else "invalid"
    if "/" in v:
        try:
            ipaddress.ip_network(v, strict=False)
            return "cidr"
        except ValueError:
            return "invalid"
    host, _ = split_host_port(v)
    try:
        ipaddress.ip_address(host)
        return "ip"
    except ValueError:
        return "domain" if _is_domain(host) else "invalid"


def _is_domain(host: str) -> bool:
    if not host or len(host) > 253 or ".." in host:
        return False
    if host.startswith(".") or host.endswith("-"):
        return False
    labels = host.split(".")
    if len(labels) < 2:
        return False
    for lab in labels:
        if not lab or len(lab) > 63:
            return False
        if not all(c.isalnum() or c == "-" for c in lab):
            return False
        if lab.startswith("-") or lab.endswith("-"):
            return False
    return True


# --------------------------------------------------------------------------- matching
@dataclass
class Decision:
    target: str
    host: str
    in_scope: bool
    reason: str
    matched_rule: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


def _rule_matches(rule: str, host: str, host_ip) -> bool:
    """Does a single scope rule match the candidate host?"""
    kind = classify(rule)
    if kind == "invalid":
        return False
    if kind == "cidr":
        if host_ip is None:
            return False
        return host_ip in ipaddress.ip_network(rule, strict=False)
    if kind == "ip":
        if host_ip is None:
            return False
        rhost, _ = split_host_port(rule)
        return host_ip == ipaddress.ip_address(rhost)
    if kind == "wildcard":
        if host_ip is not None:
            return False
        base = _strip_host(rule[2:])
        # sub-domain only, exact label boundary -> rejects look-alikes & apex
        return host != base and host.endswith("." + base)
    if kind in ("domain", "url"):
        if host_ip is not None:
            return False
        rhost, _ = split_host_port(rule if kind == "domain" else rule)
        if kind == "url":
            rhost = (urlsplit(rule).hostname or "").lower()
        return host == _strip_host(rhost)
    return False


class Scope:
    def __init__(self, data: dict):
        if not isinstance(data, dict):
            raise ScopeError("scope must be a JSON object")
        self.engagement = data.get("engagement", "")
        self.in_scope = list(data.get("in_scope", []))
        self.out_of_scope = list(data.get("out_of_scope", []))
        self.max_cidr_hosts = int(data.get("max_cidr_hosts", DEFAULT_MAX_CIDR_HOSTS))
        if not self.in_scope:
            raise ScopeError("scope.in_scope is empty — refusing to allow anything")
        bad = [r for r in self.in_scope + self.out_of_scope if classify(r) == "invalid"]
        if bad:
            raise ScopeError(f"invalid scope rule(s): {bad}")

    @classmethod
    def load(cls, path: str) -> "Scope":
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return cls(json.load(fh))
        except FileNotFoundError as exc:
            raise ScopeError(f"scope file not found: {path}") from exc
        except json.JSONDecodeError as exc:
            raise ScopeError(f"scope file is not valid JSON: {exc}") from exc

    def evaluate(self, target: str) -> Decision:
        host, _ = split_host_port(target)
        if not host:
            return Decision(target, host, False, "could not parse a host from target")
        try:
            host_ip = ipaddress.ip_address(host)
        except ValueError:
            host_ip = None
            if not _is_domain(host):
                return Decision(target, host, False, "target is neither a valid IP nor domain")
        # out-of-scope always wins
        for rule in self.out_of_scope:
            if _rule_matches(rule, host, host_ip):
                return Decision(target, host, False, "explicitly out-of-scope", rule)
        for rule in self.in_scope:
            if _rule_matches(rule, host, host_ip):
                return Decision(target, host, True, "matches in-scope rule", rule)
        return Decision(target, host, False, "no in-scope rule matched (default-deny)")


def expand_cidr(cidr: str, max_hosts: int = DEFAULT_MAX_CIDR_HOSTS) -> list[str]:
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = net.hosts() if net.num_addresses > 2 else net
    out = []
    for i, addr in enumerate(hosts):
        if i >= max_hosts:
            raise ScopeError(
                f"{cidr} exceeds max_hosts={max_hosts} ({net.num_addresses} addresses) — "
                "raise --max deliberately or narrow the range")
        out.append(str(addr))
    return out


# --------------------------------------------------------------------------- CLI
def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Executable engagement-scope guard.")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check", help="check whether a target is in-scope")
    c.add_argument("target")
    c.add_argument("--scope", required=True, help="path to scope.json")
    c.add_argument("--json", action="store_true")

    cl = sub.add_parser("classify", help="classify a scope/target string")
    cl.add_argument("value")
    cl.add_argument("--json", action="store_true")

    e = sub.add_parser("expand", help="expand a CIDR to hosts (capped)")
    e.add_argument("cidr")
    e.add_argument("--max", type=int, default=DEFAULT_MAX_CIDR_HOSTS)

    args = p.parse_args(argv)
    try:
        if args.cmd == "check":
            scope = Scope.load(args.scope)
            d = scope.evaluate(args.target)
            if args.json:
                print(json.dumps(d.to_dict()))
            else:
                flag = "IN-SCOPE" if d.in_scope else "OUT-OF-SCOPE"
                rule = f" [rule: {d.matched_rule}]" if d.matched_rule else ""
                print(f"{flag}: {d.target} -> {d.host} — {d.reason}{rule}")
            return 0 if d.in_scope else 3
        if args.cmd == "classify":
            kind = classify(args.value)
            print(json.dumps({"value": args.value, "kind": kind}) if args.json else kind)
            return 0 if kind != "invalid" else 2
        if args.cmd == "expand":
            for h in expand_cidr(args.cidr, args.max):
                print(h)
            return 0
    except ScopeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
