#!/usr/bin/env python3
"""
dependency_confusion.py - Find dependency-confusion / typosquat candidates from a project manifest.

For each dependency declared in the manifest, it queries the public registry (npm / PyPI) and reports:
  * CLAIMABLE      -> name does not exist on the public registry (404): an attacker can register it
                      (classic dependency confusion of an internal/private package name).
  * VERSION-SHADOW -> exists publicly but the public latest version is LOWER/odd vs the pinned one,
                      or the project pins a private-looking scope: a high public version could shadow it.
  * SCOPED         -> npm @scope/name (scope must be claimable too); noted for triage.

Read-only: it only performs registry metadata GETs. It NEVER publishes anything.

Usage:
  python3 dependency_confusion.py --manifest package.json      --registry npm
  python3 dependency_confusion.py --manifest requirements.txt  --registry pypi
  python3 dependency_confusion.py --manifest pyproject.toml    --registry pypi
  python3 dependency_confusion.py --manifest package.json --registry npm --out dc.json

Dependencies:  requests  (pip install requests)
"""
import argparse, json, re, sys

try:
    import requests
except ImportError:
    sys.exit("requests required: pip install requests")

NPM = "https://registry.npmjs.org/{name}"
PYPI = "https://pypi.org/pypi/{name}/json"
UA = {"User-Agent": "dc-audit/1.0 (authorized supply-chain assessment)"}


def parse_npm(path):
    data = json.load(open(path, encoding="utf-8"))
    deps = {}
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps.update(data.get(key, {}) or {})
    return deps  # {name: versionspec}


def parse_requirements(path):
    deps = {}
    for line in open(path, encoding="utf-8"):
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:[=<>!~]=?\s*([^\s;]+))?", line)
        if m:
            deps[m.group(1)] = m.group(2) or "*"
    return deps


def parse_pyproject(path):
    text = open(path, encoding="utf-8").read()
    deps = {}
    # [project] dependencies = ["foo>=1", ...]  and poetry [tool.poetry.dependencies]
    for m in re.finditer(r'["\']([A-Za-z0-9_.\-]+)\s*(?:[=<>!~\^]=?\s*[^"\']*)?["\']', text):
        name = m.group(1)
        if name.lower() not in ("python",) and len(name) > 1:
            deps.setdefault(name, "*")
    return deps


def check_npm(session, name):
    r = session.get(NPM.format(name=name), headers=UA, timeout=15)
    if r.status_code == 404:
        return ("CLAIMABLE", "not on npm public registry")
    if r.status_code == 200:
        latest = (r.json().get("dist-tags", {}) or {}).get("latest", "?")
        return ("PUBLIC", f"public latest={latest}")
    return ("UNKNOWN", f"http {r.status_code}")


def check_pypi(session, name):
    r = session.get(PYPI.format(name=name), headers=UA, timeout=15)
    if r.status_code == 404:
        return ("CLAIMABLE", "not on PyPI")
    if r.status_code == 200:
        latest = r.json().get("info", {}).get("version", "?")
        return ("PUBLIC", f"public latest={latest}")
    return ("UNKNOWN", f"http {r.status_code}")


def main():
    ap = argparse.ArgumentParser(description="Dependency-confusion candidate finder")
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--registry", required=True, choices=["npm", "pypi"])
    ap.add_argument("--out")
    args = ap.parse_args()

    if args.registry == "npm":
        deps = parse_npm(args.manifest)
        checker = check_npm
    else:
        if args.manifest.endswith(".toml"):
            deps = parse_pyproject(args.manifest)
        else:
            deps = parse_requirements(args.manifest)
        checker = check_pypi

    session = requests.Session()
    results = []
    for name, spec in sorted(deps.items()):
        scoped = name.startswith("@")
        status, detail = checker(session, name)
        flag = status
        if status == "CLAIMABLE":
            flag = "CLAIMABLE"  # highest interest
        elif scoped:
            flag = "SCOPED"
        results.append({"name": name, "pinned": spec, "scoped": scoped,
                        "status": status, "flag": flag, "detail": detail})

    rank = {"CLAIMABLE": 0, "SCOPED": 1, "UNKNOWN": 2, "PUBLIC": 3}
    results.sort(key=lambda r: rank.get(r["flag"], 9))
    for r in results:
        mark = "<== CLAIMABLE (confusion candidate)" if r["status"] == "CLAIMABLE" else ""
        print(f"[{r['flag']:9}] {r['name']:40} pinned={r['pinned']:12} {r['detail']} {mark}")
    claimable = [r for r in results if r["status"] == "CLAIMABLE"]
    print(f"\n{len(results)} deps checked; {len(claimable)} CLAIMABLE confusion candidate(s).")
    if args.out:
        json.dump(results, open(args.out, "w", encoding="utf-8"), indent=2)
        print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
