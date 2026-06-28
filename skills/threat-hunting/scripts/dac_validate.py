#!/usr/bin/env python3
"""
dac_validate.py - Detection-as-Code validator / compiler for Sigma rule repos.

Gates a CI merge: lints every Sigma rule for schema + DaC policy (unique UUID, required
ATT&CK tags, sane level), then optionally compiles to a SIEM backend via sigma-cli.

USAGE:
    python3 dac_validate.py <rules_dir> [--backend splunk|microsoft365defender|elasticsearch]
                            [--pipeline sysmon] [--fail-on-error] [--out compiled.txt]

DEPENDENCIES:
    pip install pyyaml
    # for --backend compilation:
    pip install sigma-cli pysigma-backend-splunk pysigma-backend-microsoft365defender \
                pysigma-backend-elasticsearch pysigma-pipeline-sysmon

EXIT CODE: non-zero if any rule fails policy (with --fail-on-error) -> breaks the build.

This is a defensive detection-engineering tool. Authorized use only.
"""
import argparse
import re
import subprocess
import sys
import uuid as uuidlib
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("Install pyyaml: pip install pyyaml")

ATTACK_TAG = re.compile(r"^attack\.t\d{4}(\.\d{3})?$", re.IGNORECASE)
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
VALID_STATUS = {"experimental", "test", "stable", "deprecated", "unsupported"}


def load_yaml_docs(path: Path):
    """Yield each YAML document in a file (Sigma files may bundle multiple with '---')."""
    text = path.read_text(encoding="utf-8", errors="replace")
    for doc in yaml.safe_load_all(text):
        if isinstance(doc, dict):
            yield doc


def lint_rule(rule: dict, path: Path, seen_ids: dict) -> list:
    """Return a list of (severity, message) policy findings for one Sigma rule."""
    findings = []
    name = rule.get("title", "<no title>")

    # Correlation rules have a different shape; lint the parts that still apply.
    is_corr = "correlation" in rule

    rid = rule.get("id")
    if not rid:
        findings.append(("ERROR", f"{name}: missing 'id' (UUID required)"))
    else:
        try:
            uuidlib.UUID(str(rid))
        except (ValueError, AttributeError, TypeError):
            findings.append(("ERROR", f"{name}: id '{rid}' is not a valid UUID"))
        if rid in seen_ids:
            findings.append(("ERROR", f"{name}: duplicate id '{rid}' (also in {seen_ids[rid]})"))
        else:
            seen_ids[rid] = str(path)

    if not rule.get("title"):
        findings.append(("ERROR", f"{path}: rule missing 'title'"))

    status = rule.get("status")
    if status and status not in VALID_STATUS:
        findings.append(("WARN", f"{name}: unknown status '{status}'"))

    level = rule.get("level")
    if not is_corr and not level:
        findings.append(("WARN", f"{name}: missing 'level'"))
    elif level and level not in VALID_LEVELS:
        findings.append(("ERROR", f"{name}: invalid level '{level}'"))

    tags = rule.get("tags") or []
    attack_tags = [t for t in tags if str(t).lower().startswith("attack.t")]
    if not attack_tags:
        findings.append(("ERROR", f"{name}: no ATT&CK technique tag (need e.g. attack.t1059.001)"))
    for t in attack_tags:
        if not ATTACK_TAG.match(str(t)):
            findings.append(("WARN", f"{name}: malformed ATT&CK tag '{t}'"))

    if not is_corr:
        if "logsource" not in rule:
            findings.append(("ERROR", f"{name}: missing 'logsource'"))
        det = rule.get("detection")
        if not det or "condition" not in det:
            findings.append(("ERROR", f"{name}: detection block missing 'condition'"))
        if not rule.get("falsepositives"):
            findings.append(("WARN", f"{name}: no 'falsepositives' documented"))

    return findings


def compile_backend(rules_dir: Path, backend: str, pipeline: str, out: str) -> int:
    """Shell out to sigma-cli to convert the directory; returns its exit code."""
    cmd = ["sigma", "convert", "-t", backend]
    if pipeline:
        cmd += ["-p", pipeline]
    cmd += [str(rules_dir)]
    if out:
        cmd += ["-o", out]
    print(f"[*] Compiling: {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        print("[!] sigma-cli not found. pip install sigma-cli + the backend plugin.", file=sys.stderr)
        return 127
    if proc.stdout and not out:
        print(proc.stdout)
    if proc.returncode != 0:
        print(f"[!] sigma convert failed:\n{proc.stderr}", file=sys.stderr)
    else:
        print(f"[+] Compiled to {backend}" + (f" -> {out}" if out else ""))
    return proc.returncode


def main():
    ap = argparse.ArgumentParser(description="Detection-as-Code Sigma validator/compiler")
    ap.add_argument("rules_dir", help="directory of Sigma .yml rules")
    ap.add_argument("--backend", help="sigma-cli target backend to compile to")
    ap.add_argument("--pipeline", default="", help="sigma-cli processing pipeline (e.g. sysmon)")
    ap.add_argument("--out", default="", help="write compiled queries to this file")
    ap.add_argument("--fail-on-error", action="store_true",
                    help="exit non-zero if any ERROR finding (CI gate)")
    args = ap.parse_args()

    rules_dir = Path(args.rules_dir)
    files = sorted(rules_dir.rglob("*.yml")) + sorted(rules_dir.rglob("*.yaml"))
    if not files:
        sys.exit(f"No .yml/.yaml rules under {rules_dir}")

    seen_ids: dict = {}
    errors = warns = 0
    print(f"[*] Linting {len(files)} Sigma file(s) in {rules_dir}\n")

    for f in files:
        try:
            for rule in load_yaml_docs(f):
                for sev, msg in lint_rule(rule, f, seen_ids):
                    print(f"  [{sev}] {msg}")
                    if sev == "ERROR":
                        errors += 1
                    else:
                        warns += 1
        except yaml.YAMLError as e:
            print(f"  [ERROR] {f}: YAML parse error: {e}")
            errors += 1

    print(f"\n[=] Lint complete: {errors} error(s), {warns} warning(s)")

    rc = 0
    if args.backend:
        rc = compile_backend(rules_dir, args.backend, args.pipeline, args.out)

    if args.fail_on_error and (errors > 0 or rc != 0):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
