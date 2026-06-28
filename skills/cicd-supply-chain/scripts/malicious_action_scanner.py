#!/usr/bin/env python3
"""
malicious_action_scanner.py - Audit a repo's GitHub Actions `uses:` refs and package install hooks
for supply-chain exposure.

Checks:
  --check-pins        Flag every `uses:` ref that is NOT pinned to a 40-char commit SHA (tags/branches
                      are MUTABLE and can be re-pointed to malicious commits, e.g. CVE-2025-30066).
  --check-known-bad   Flag references to actions with publicly-known compromise history / the
                      tj-actions malicious SHA, and scan vendored action/payload source for IOCs
                      (trufflehog filesystem, shai-hulud, webhook.site, toJSON(secrets), double-base64).
  --resolve TOKEN     Resolve each tag to the SHA it currently points to (GitHub API) so you can diff
                      against a recorded baseline and catch a re-point.

Also scans package manifests / lockfiles for install-time hooks (preinstall/install/postinstall) and
the Shai-Hulud worm IOCs (bundle.js, shai-hulud-workflow.yml).

Usage:
  python3 malicious_action_scanner.py --path ./repo --check-pins --check-known-bad
  python3 malicious_action_scanner.py --path ./repo --resolve "$GH_TOKEN" --baseline baseline.json

Dependencies:  PyYAML (pip install pyyaml); requests only for --resolve (pip install requests)
"""
import argparse, hashlib, json, os, re, sys

try:
    import yaml  # noqa: F401  (used indirectly via regex; kept for parity / future use)
except ImportError:
    yaml = None

SHA40 = re.compile(r"^[0-9a-f]{40}$")
USES = re.compile(r"(?m)^\s*-?\s*uses:\s*([^\s#]+)")
# action@ref  (ref = tag / branch / sha)
REF = re.compile(r"^(?P<action>[^@]+)@(?P<ref>.+)$")

KNOWN_BAD_ACTIONS = {
    "tj-actions/changed-files": "CVE-2025-30066: tags re-pointed to malicious commit (Mar 2025)",
    "reviewdog/action-setup": "CVE-2025-30154: v1 tag re-pointed to malicious commit (Mar 2025)",
    "tj-actions/eslint-changed-files": "transitively pulled the compromised reviewdog action",
}
KNOWN_BAD_SHA = {
    "0e58ed8671d6b60d0890c21b07f8835ace038e67": "tj-actions/changed-files malicious commit (CVE-2025-30066)",
}
# Shai-Hulud npm worm payload bundle.js
SHAI_HULUD_BUNDLE_SHA256 = "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09"

SOURCE_IOCS = [
    (re.compile(r"trufflehog\s+filesystem", re.I), "trufflehog filesystem scan (worm credential harvest)"),
    (re.compile(r"shai[-_]?hulud", re.I), "shai-hulud worm string"),
    (re.compile(r"webhook\.site", re.I), "webhook.site exfil endpoint (worm/GhostAction class)"),
    (re.compile(r"toJSON\(\s*secrets\s*\)", re.I), "toJSON(secrets) full secret-context exfil"),
    (re.compile(r"NpmModule\.updatePackage", re.I), "worm self-replication routine"),
    (re.compile(r"[A-Za-z0-9+/]{200,}={0,2}", ), "very long base64 blob (possible staged/double-encoded payload)"),
]
HOOK_KEYS = ("preinstall", "install", "postinstall", "prepare", "preuninstall")


def add(f, sev, fpath, code, detail):
    f.append({"severity": sev, "file": fpath, "code": code, "detail": detail})


def scan_workflows(path, findings, check_pins, check_known_bad):
    wf_dir = os.path.join(path, ".github", "workflows")
    if not os.path.isdir(wf_dir):
        return []
    refs = []
    for fn in os.listdir(wf_dir):
        if not fn.endswith((".yml", ".yaml")):
            continue
        fp = os.path.join(wf_dir, fn)
        text = open(fp, encoding="utf-8", errors="replace").read()
        rel = os.path.join(".github/workflows", fn)
        for m in USES.finditer(text):
            ref_full = m.group(1).strip().strip("'\"")
            rm = REF.match(ref_full)
            if not rm:  # local (./...) or docker:// action
                continue
            action, ref = rm.group("action"), rm.group("ref")
            refs.append({"file": rel, "action": action, "ref": ref})
            if check_pins and not SHA40.match(ref):
                add(findings, "MEDIUM", rel, "unpinned_action",
                    f"{action}@{ref} pinned to a MUTABLE tag/branch (pin to a 40-char SHA)")
            if check_known_bad:
                if action in KNOWN_BAD_ACTIONS:
                    add(findings, "CRITICAL", rel, "known_bad_action",
                        f"{action} -- {KNOWN_BAD_ACTIONS[action]}")
                if ref.lower() in KNOWN_BAD_SHA:
                    add(findings, "CRITICAL", rel, "known_bad_sha",
                        f"{action}@{ref} -- {KNOWN_BAD_SHA[ref.lower()]}")
    return refs


def scan_source_iocs(path, findings):
    exts = (".js", ".mjs", ".cjs", ".ts", ".py", ".sh", ".yml", ".yaml")
    for root, dirs, files in os.walk(path):
        if ".git" in dirs:
            dirs.remove(".git")
        for fn in files:
            fp = os.path.join(root, fn)
            rel = os.path.relpath(fp, path)
            if fn == "shai-hulud-workflow.yml" or fn == "bundle.js":
                # hash bundle.js to confirm the worm payload
                try:
                    h = hashlib.sha256(open(fp, "rb").read()).hexdigest()
                except OSError:
                    h = "?"
                sev = "CRITICAL" if (fn == "bundle.js" and h == SHAI_HULUD_BUNDLE_SHA256) else "HIGH"
                add(findings, sev, rel, "shai_hulud_ioc",
                    f"{fn} present (sha256={h}) -- Shai-Hulud worm artifact"
                    + (" [HASH MATCH]" if h == SHAI_HULUD_BUNDLE_SHA256 else ""))
            if not fn.endswith(exts):
                continue
            try:
                if os.path.getsize(fp) > 8 * 1024 * 1024:
                    continue
                text = open(fp, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            for rx, desc in SOURCE_IOCS:
                if rx.search(text):
                    add(findings, "HIGH", rel, "source_ioc", desc)
                    break  # one IOC class per file is enough signal


def scan_install_hooks(path, findings):
    pj = os.path.join(path, "package.json")
    if os.path.isfile(pj):
        try:
            data = json.load(open(pj, encoding="utf-8"))
            for k in HOOK_KEYS:
                if k in (data.get("scripts") or {}):
                    add(findings, "MEDIUM", "package.json", "install_hook",
                        f"npm `{k}` hook runs code at install: {data['scripts'][k]!r} (use --ignore-scripts in CI)")
        except (ValueError, OSError):
            pass
    for setup in ("setup.py",):
        sp = os.path.join(path, setup)
        if os.path.isfile(sp):
            t = open(sp, encoding="utf-8", errors="replace").read()
            if re.search(r"cmdclass|class\s+\w+\(install\)|os\.system|subprocess", t):
                add(findings, "MEDIUM", setup, "install_hook",
                    "setup.py runs code at install time (custom cmdclass/os.system/subprocess)")


def resolve_tags(refs, token, baseline_path, findings):
    import requests
    s = requests.Session()
    s.headers.update({"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"})
    baseline = {}
    if baseline_path and os.path.isfile(baseline_path):
        baseline = json.load(open(baseline_path, encoding="utf-8"))
    current = {}
    for r in refs:
        action, ref = r["action"], r["ref"]
        if SHA40.match(ref) or "/" not in action:
            continue
        # try tag then branch
        sha = None
        for kind in ("tags", "heads"):
            resp = s.get(f"https://api.github.com/repos/{action}/git/ref/{kind}/{ref}")
            if resp.status_code == 200:
                sha = resp.json().get("object", {}).get("sha")
                break
        if sha:
            key = f"{action}@{ref}"
            current[key] = sha
            if key in baseline and baseline[key] != sha:
                add(findings, "CRITICAL", r["file"], "tag_repoint",
                    f"{key} now resolves to {sha} (was {baseline[key]}) -- possible action compromise")
    out = (baseline_path or "action_baseline.json")
    json.dump(current, open(out, "w", encoding="utf-8"), indent=2)
    print(f"recorded {len(current)} tag->SHA resolutions to {out}")


def main():
    ap = argparse.ArgumentParser(description="Scan actions + install hooks for supply-chain exposure")
    ap.add_argument("--path", required=True)
    ap.add_argument("--check-pins", action="store_true")
    ap.add_argument("--check-known-bad", action="store_true")
    ap.add_argument("--resolve", metavar="GH_TOKEN", help="resolve tags to SHAs via GitHub API")
    ap.add_argument("--baseline", help="baseline JSON of action@ref->SHA to diff against (re-point detection)")
    ap.add_argument("--out")
    args = ap.parse_args()

    # default: do all static checks if no specific switch given
    if not (args.check_pins or args.check_known_bad):
        args.check_pins = args.check_known_bad = True

    findings = []
    refs = scan_workflows(args.path, findings, args.check_pins, args.check_known_bad)
    if args.check_known_bad:
        scan_source_iocs(args.path, findings)
    scan_install_hooks(args.path, findings)
    if args.resolve:
        resolve_tags(refs, args.resolve, args.baseline, findings)

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: order.get(f["severity"], 9))
    for f in findings:
        print(f"[{f['severity']:8}] {f['file']:40} {f['code']:18} -- {f['detail']}")
    print(f"\n{len(refs)} action ref(s); {len(findings)} finding(s).")
    if args.out:
        json.dump(findings, open(args.out, "w", encoding="utf-8"), indent=2)
        print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
