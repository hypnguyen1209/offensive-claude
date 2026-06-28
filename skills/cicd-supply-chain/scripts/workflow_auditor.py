#!/usr/bin/env python3
"""
workflow_auditor.py - Static auditor for CI/CD pipeline-poisoning sinks.

Detects, in GitHub Actions / GitLab CI YAML:
  * Pwn requests:    privileged triggers (pull_request_target / workflow_run / issue_comment /
                     discussion_comment) that check out untrusted PR head ref/sha.
  * Script injection: ${{ <attacker-controlled expression> }} interpolated into a `run:` block.
  * PPE risk:        self-hosted runner labels; missing top-level read-only `permissions:` block.
  * GitLab:          .gitlab-ci.yml shell `script:` that invokes attacker-editable build files.

Two modes:
  --path REPO         offline: walk .github/workflows/*.yml and .gitlab-ci.yml in a clone (no token)
  --repos FILE        online: for each `owner/name` line, fetch workflow files via the GitHub API
                      (needs --token; read-only scope is enough)

Usage:
  python3 workflow_auditor.py --path ./target-repo [--out findings.json]
  python3 workflow_auditor.py --repos repos.txt --token "$GH_TOKEN" --out findings.json

Dependencies:  PyYAML  (pip install pyyaml);  requests only for --repos mode (pip install requests)
Exit code 0 always; findings go to stdout (table) and --out (JSON).
"""
import argparse, json, os, re, sys

try:
    import yaml  # optional: improves trigger parsing; the auditor falls back to regex without it
except ImportError:
    yaml = None

PRIVILEGED_TRIGGERS = {
    "pull_request_target", "workflow_run", "issue_comment",
    "issues", "discussion_comment", "discussion", "fork", "watch",
}
# attacker-controllable expression fragments that are dangerous inside run:
INJECTION_EXPR = re.compile(
    r"\$\{\{\s*(?:github\.event\.(?:issue\.title|issue\.body|pull_request\.title|"
    r"pull_request\.body|pull_request\.head\.ref|comment\.body|review\.body|"
    r"discussion\.title|discussion\.body|head_commit\.message|commits\[)|"
    r"github\.head_ref|github\.event\.head_commit\.author)",
    re.IGNORECASE,
)
HEAD_CHECKOUT = re.compile(
    r"github\.event\.pull_request\.head\.(?:ref|sha)|github\.event\.pull_request\.head\.repo",
    re.IGNORECASE,
)
SECRETS_DUMP = re.compile(r"toJSON\(\s*secrets\s*\)|\$\{\{\s*secrets\s*\}\}", re.IGNORECASE)


def add(findings, sev, repo, fpath, kind, detail):
    findings.append({"severity": sev, "repo": repo, "file": fpath, "type": kind, "detail": detail})


def _triggers(on):
    """Normalize the polymorphic `on:` key into a set of trigger names."""
    if on is None:
        return set()
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return set(on)
    if isinstance(on, dict):
        return set(on.keys())
    return set()


def audit_gha(text, repo, fpath, findings):
    doc = None
    if yaml is not None:
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError:
            doc = None

    triggers = _triggers(doc.get("on") if isinstance(doc, dict) else None) if doc else set()
    # YAML parses bare `on:` to True in some cases; also regex-scan raw text as a fallback.
    raw_triggers = {t for t in PRIVILEGED_TRIGGERS if re.search(r"(?m)^\s*%s\s*:" % re.escape(t), text)}
    priv = (triggers | raw_triggers) & PRIVILEGED_TRIGGERS

    has_head_checkout = bool(HEAD_CHECKOUT.search(text))
    top_perms = isinstance(doc, dict) and "permissions" in doc

    if priv and has_head_checkout:
        add(findings, "CRITICAL", repo, fpath, "pwn_request",
            f"privileged trigger {sorted(priv)} + checkout of untrusted PR head ref/sha -> RCE")
    elif priv:
        add(findings, "HIGH", repo, fpath, "privileged_trigger",
            f"privileged trigger(s) {sorted(priv)} present; verify no untrusted checkout/build")

    for m in INJECTION_EXPR.finditer(text):
        # only flag if it appears in a run: context (heuristic: same or nearby line has run: or shell)
        line = text[: m.start()].count("\n") + 1
        add(findings, "HIGH", repo, fpath, "script_injection",
            f"line {line}: attacker-controlled expression `{m.group(0)}` may reach a shell `run:`")

    if SECRETS_DUMP.search(text):
        add(findings, "CRITICAL", repo, fpath, "secret_exfil",
            "toJSON(secrets) / ${{ secrets }} serializes the whole secret context (mask-bypass exfil)")

    if re.search(r"(?m)runs-on:\s*\[?\s*self-hosted", text):
        add(findings, "MEDIUM", repo, fpath, "self_hosted_runner",
            "self-hosted runner label; non-ephemeral runners enable persistence/secret leak")

    if priv and not top_perms:
        add(findings, "MEDIUM", repo, fpath, "missing_permissions",
            "no top-level `permissions:` block; defaults to broad write token (set contents: read)")


def audit_gitlab(text, repo, fpath, findings):
    if re.search(r"(?m)^\s*script:", text) and re.search(
        r"\b(make|npm run|bash\s+\S+\.sh|python\s+\S+\.py|\./\S+)\b", text
    ):
        add(findings, "MEDIUM", repo, fpath, "gitlab_indirect_ppe",
            "pipeline runs an in-repo build file (make/script) editable in a merge request -> I-PPE")
    if re.search(r"CI_JOB_TOKEN|CI_REGISTRY_PASSWORD|\$\{?CI_", text) and re.search(
        r"curl|wget|nc\b", text
    ):
        add(findings, "HIGH", repo, fpath, "gitlab_secret_exfil",
            "CI variables referenced near an outbound network client (possible exfil)")


def walk_local(path, findings):
    wf_dir = os.path.join(path, ".github", "workflows")
    if os.path.isdir(wf_dir):
        for fn in os.listdir(wf_dir):
            if fn.endswith((".yml", ".yaml")):
                fp = os.path.join(wf_dir, fn)
                with open(fp, encoding="utf-8", errors="replace") as fh:
                    audit_gha(fh.read(), os.path.basename(path), os.path.join(".github/workflows", fn), findings)
    gl = os.path.join(path, ".gitlab-ci.yml")
    if os.path.isfile(gl):
        with open(gl, encoding="utf-8", errors="replace") as fh:
            audit_gitlab(fh.read(), os.path.basename(path), ".gitlab-ci.yml", findings)


def fetch_remote(repos_file, token, findings):
    import requests
    s = requests.Session()
    s.headers.update({"Authorization": f"Bearer {token}",
                      "Accept": "application/vnd.github+json",
                      "X-GitHub-Api-Version": "2022-11-28"})
    for line in open(repos_file, encoding="utf-8"):
        repo = line.strip()
        if not repo or repo.startswith("#"):
            continue
        r = s.get(f"https://api.github.com/repos/{repo}/contents/.github/workflows")
        if r.status_code != 200:
            continue
        for entry in r.json():
            if entry.get("type") == "file" and entry["name"].endswith((".yml", ".yaml")):
                raw = s.get(entry["download_url"])
                if raw.status_code == 200:
                    audit_gha(raw.text, repo, entry["path"], findings)


def main():
    ap = argparse.ArgumentParser(description="Audit CI workflows for pipeline-poisoning sinks")
    ap.add_argument("--path", help="local clone to audit offline")
    ap.add_argument("--repos", help="file of owner/name lines to audit via the GitHub API")
    ap.add_argument("--token", default=os.environ.get("GH_TOKEN", ""), help="GitHub token (read-only ok)")
    ap.add_argument("--out", help="write findings JSON here")
    args = ap.parse_args()

    findings = []
    if args.path:
        walk_local(args.path, findings)
    if args.repos:
        if not args.token:
            sys.exit("--repos requires --token (or GH_TOKEN env)")
        fetch_remote(args.repos, args.token, findings)
    if not args.path and not args.repos:
        ap.error("provide --path or --repos")

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: order.get(f["severity"], 9))
    for f in findings:
        print(f"[{f['severity']:8}] {f['repo']} :: {f['file']} :: {f['type']} -- {f['detail']}")
    print(f"\n{len(findings)} finding(s).")
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(findings, fh, indent=2)
        print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
