#!/usr/bin/env python3
"""hackerone_public_recon.py - pull a PUBLIC HackerOne program's scope/policy as recon input.

Generic (works for any program handle), stdlib-only, no auth, no SDK. Useful as a recon
*input* (public, disclosed scope intel) - we are a broad red-team toolkit, not a bug-bounty
client, so this is optional and read-only.

We do NOT vendor anyone's fragile GraphQL wrapper. This builds the request, fetches
defensively (timeout, graceful failure), and parses HackerOne's public `structured_scopes`
shape into our scope vocabulary.

!! A bug-bounty program's published scope is NOT your engagement authorization. It tells you
   what the *program* considers in/out of scope; you still need your own written authorization
   (see TERMS.md). `--out scope.json` writes a CANDIDATE you must review, never an ROE.

CLI:
  hackerone_public_recon.py --handle <program> [--json] [--out candidate-scope.json]
  exit 0 ok, 2 error/unreachable
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from typing import Optional

UA = "offensive-claude-recon/1.0 (+authorized security research)"

# HackerOne asset types -> how we represent them. WILDCARD/URL/CIDR/IP map cleanly.
_ASSET_KEEP = {"WILDCARD", "URL", "CIDR", "IP_ADDRESS", "DOMAIN"}


def graphql_query(handle: str) -> dict:
    """Public GraphQL query for a program's structured scopes. (Endpoint/shape is
    unofficial and may change - if it breaks, update this query, not the parser.)"""
    return {
        "query": (
            "query($handle:String!){team(handle:$handle){handle "
            "structured_scopes(first:200){edges{node{asset_identifier asset_type "
            "eligible_for_submission instruction}}}}}"
        ),
        "variables": {"handle": handle},
    }


def fetch_scopes(handle: str, timeout: float = 15.0, opener=None) -> dict:
    """Fetch raw GraphQL JSON for a program. `opener` is injectable for testing."""
    body = json.dumps(graphql_query(handle)).encode("utf-8")
    req = urllib.request.Request(
        "https://hackerone.com/graphql", data=body,
        headers={"Content-Type": "application/json", "User-Agent": UA, "Accept": "application/json"},
    )
    op = opener or urllib.request.urlopen
    with op(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def parse_structured_scopes(data: dict) -> dict:
    """Turn HackerOne's structured_scopes JSON into {in_scope:[], out_of_scope:[], assets:[]}."""
    in_scope, out_of_scope, assets = [], [], []
    try:
        edges = data["data"]["team"]["structured_scopes"]["edges"]
    except (KeyError, TypeError):
        edges = []
    for edge in edges:
        node = (edge or {}).get("node") or {}
        ident = (node.get("asset_identifier") or "").strip()
        atype = (node.get("asset_type") or "").upper()
        if not ident:
            continue
        assets.append({"identifier": ident, "type": atype,
                       "eligible": bool(node.get("eligible_for_submission"))})
        if atype not in _ASSET_KEEP:
            continue  # mobile app ids, source code, etc. - not a network target
        (in_scope if node.get("eligible_for_submission") else out_of_scope).append(ident)
    # de-dupe, preserve order
    return {
        "in_scope": list(dict.fromkeys(in_scope)),
        "out_of_scope": list(dict.fromkeys(out_of_scope)),
        "assets": assets,
    }


def to_candidate_scope(parsed: dict, handle: str) -> dict:
    return {
        "engagement": f"hackerone:{handle} (CANDIDATE - confirm your own authorization)",
        "authorization_ref": "REPLACE-ME: this is the program's public scope, NOT your ROE",
        "in_scope": parsed["in_scope"],
        "out_of_scope": parsed["out_of_scope"],
        "max_cidr_hosts": 1024,
    }


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Fetch a public HackerOne program's scope (recon input).")
    p.add_argument("--handle", required=True, help="program handle, e.g. 'security'")
    p.add_argument("--out", help="write a CANDIDATE scope.json (review before use)")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    try:
        raw = fetch_scopes(args.handle)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, ValueError) as exc:
        print(f"error: could not fetch program '{args.handle}': {exc}", file=sys.stderr)
        return 2

    parsed = parse_structured_scopes(raw)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(to_candidate_scope(parsed, args.handle), fh, indent=2)
        print(f"wrote candidate scope to {args.out} - REVIEW IT; it is not your authorization", file=sys.stderr)

    if args.json:
        print(json.dumps(parsed, indent=2))
    else:
        print(f"# {args.handle}: {len(parsed['in_scope'])} in-scope, {len(parsed['out_of_scope'])} out-of-scope")
        for a in parsed["in_scope"]:
            print(f"IN   {a}")
        for a in parsed["out_of_scope"]:
            print(f"OUT  {a}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
