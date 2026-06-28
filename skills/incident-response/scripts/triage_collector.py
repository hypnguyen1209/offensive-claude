#!/usr/bin/env python3
"""
triage_collector.py - Cross-platform IR triage orchestrator + suspect-tooling verifier.

Purpose:
  1. Drive an order-of-volatility-respecting live-response collection on the local host using the
     best available tool (Velociraptor offline collector / KAPE on Windows; UAC / CatScale on Unix).
  2. Verify any Velociraptor instance found on the host is NOT adversary persistence
     (CVE-2025-6264, abused as <0.73.5; Talos/Storm-2603, Aug 2025).

Usage:
  # Build/run a local triage collection (auto-detect OS), writing OFF the suspect volume:
  python3 triage_collector.py --os auto --out /evidence
  # Prefer a Velociraptor offline collector if velociraptor[.exe] + server config are present:
  python3 triage_collector.py --os auto --out /evidence --velociraptor-collector \
      --vr-config server.config.yaml
  # ONLY run the Velociraptor persistence check (CVE-2025-6264):
  python3 triage_collector.py --check-velociraptor
  # Dry-run (print the commands, change nothing):
  python3 triage_collector.py --os auto --out /evidence --dry-run

Dependencies: Python 3.8+ (stdlib only). The external collectors (velociraptor, kape.exe, uac,
  Cat-Scale.sh) must be discoverable on PATH or passed via the corresponding flag.
Notes: collecting on a LIVE host mutates volatile state; capture RAM first (see references/
  triage-collection.md). Run with admin/root. Output is written off-host where possible.
"""
import argparse
import datetime
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys

PATCHED_VELOCIRAPTOR = (0, 73, 5)  # CVE-2025-6264 fixed in 0.73.5


def now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def log(msg: str) -> None:
    print(f"[{now()}] {msg}", flush=True)


def run(cmd, dry_run: bool):
    log("RUN: " + " ".join(cmd))
    if dry_run:
        return 0, ""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)
        if p.stdout:
            print(p.stdout)
        if p.returncode != 0 and p.stderr:
            print(p.stderr, file=sys.stderr)
        return p.returncode, p.stdout
    except FileNotFoundError:
        log(f"!! tool not found: {cmd[0]}")
        return 127, ""
    except subprocess.TimeoutExpired:
        log("!! collection timed out")
        return 124, ""


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def which(name: str):
    return shutil.which(name)


# ---------------------------------------------------------------- Velociraptor verification
def _parse_version(text: str):
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", text or "")
    return tuple(int(x) for x in m.groups()) if m else None


def check_velociraptor() -> dict:
    """Look for Velociraptor on-host and assess CVE-2025-6264 exposure / persistence IOCs."""
    findings = {"found": False, "version": None, "vulnerable": None, "iocs": [], "paths": []}
    candidates = []
    is_win = platform.system().lower().startswith("win")

    if is_win:
        for root in (os.environ.get("ProgramFiles", r"C:\Program Files"),
                     os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
                     r"C:\Windows\Temp", r"C:\ProgramData"):
            if root and os.path.isdir(root):
                for dirpath, _dirs, files in os.walk(root):
                    for f in files:
                        if f.lower().startswith("velociraptor") and f.lower().endswith(".exe"):
                            candidates.append(os.path.join(dirpath, f))
                    if dirpath.count(os.sep) - root.count(os.sep) > 3:
                        _dirs[:] = []  # bound the walk depth
        # service-based discovery
        rc, out = run(["sc", "query", "type=", "service", "state=", "all"], dry_run=False)
        # (best-effort; PathName via wmic below)
        rc, out = run(["wmic", "service", "where",
                       "PathName like '%velociraptor%'", "get", "Name,PathName,StartMode"],
                      dry_run=False)
        if "velociraptor" in (out or "").lower():
            findings["iocs"].append("velociraptor service present: " + out.strip())
    else:
        w = which("velociraptor")
        if w:
            candidates.append(w)
        for p in ("/usr/local/bin/velociraptor", "/opt/velociraptor/velociraptor",
                  "/tmp/velociraptor"):
            if os.path.exists(p):
                candidates.append(p)

    candidates = sorted(set(candidates))
    findings["paths"] = candidates
    if not candidates:
        return findings

    findings["found"] = True
    for c in candidates:
        rc, out = run([c, "version"], dry_run=False)
        ver = _parse_version(out)
        if ver:
            findings["version"] = ".".join(map(str, ver))
            findings["vulnerable"] = ver < PATCHED_VELOCIRAPTOR
            if ver < PATCHED_VELOCIRAPTOR:
                findings["iocs"].append(
                    f"{c}: version {findings['version']} < 0.73.5 -> CVE-2025-6264 vulnerable "
                    f"(known abused build 0.73.4.0)")
            break

    # Persistence-abuse heuristics (Talos): MSI from Azure Blob, relaunch after isolation.
    findings["iocs"].append(
        "MANUAL: confirm this Velociraptor matches YOUR deployment; "
        "check installer origin (*.blob.core.windows.net = IOC) and whether the service "
        "relaunches after host isolation.")
    return findings


# ---------------------------------------------------------------- collectors
def collect_windows(args) -> None:
    out = os.path.join(args.out, f"triage-{platform.node()}-{now()}")
    os.makedirs(out, exist_ok=True)

    if args.velociraptor_collector:
        vr = args.vr_bin or which("velociraptor") or "velociraptor"
        coll = os.path.join(out, "WinTriage.exe")
        build = [vr, "--config", args.vr_config or "server.config.yaml", "collector",
                 "--target", "ZIP", "--output", coll,
                 "artifacts", "add", "Windows.KapeFiles.Targets",
                 "--args", "Device=C:", "--args", "_SANS_Triage=Y",
                 "artifacts", "add", "Windows.Memory.Acquisition"]
        rc, _ = run(build, args.dry_run)
        if rc == 0 and not args.dry_run and os.path.exists(coll):
            log(f"built offline collector {coll}; run it on the endpoint to produce a Collection zip")
        return

    kape = args.kape_bin or which("kape") or which("kape.exe")
    if kape:
        run([kape, "--tsource", "C:", "--tdest", out, "--target", "!SANS_Triage",
             "--zip", platform.node()], args.dry_run)
    else:
        log("!! No Velociraptor/KAPE found. Install one or pass --kape-bin/--vr-bin.")


def collect_unix(args) -> None:
    out = os.path.join(args.out, f"triage-{platform.node()}-{now()}")
    os.makedirs(out, exist_ok=True)
    uac = args.uac_bin or which("uac")
    cat = args.catscale_bin or which("Cat-Scale.sh")
    if uac:
        run([uac, "-p", "ir_triage", out], args.dry_run)
    elif cat:
        run(["bash", cat], args.dry_run)
    else:
        log("!! No UAC/CatScale found. Falling back to a minimal stdlib volatile snapshot.")
        _minimal_unix_snapshot(out, args.dry_run)


def _minimal_unix_snapshot(out: str, dry_run: bool) -> None:
    """Last-resort order-of-volatility snapshot using base tools."""
    steps = {
        "processes.txt": ["ps", "-eo", "pid,ppid,user,stime,etime,cmd"],
        "netstat.txt": ["ss", "-tanp"],
        "listening.txt": ["ss", "-lntup"],
        "loaded_modules.txt": ["lsmod"],
        "logged_in.txt": ["w"],
        "ld_so_preload.txt": ["cat", "/etc/ld.so.preload"],  # eBPF userland-hook IOC
        "crontab_root.txt": ["crontab", "-l"],
    }
    for fname, cmd in steps.items():
        if dry_run:
            log("RUN(>%s): %s" % (fname, " ".join(cmd)))
            continue
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            with open(os.path.join(out, fname), "w", encoding="utf-8") as fh:
                fh.write(r.stdout + ("\n[stderr]\n" + r.stderr if r.stderr else ""))
        except Exception as e:  # noqa: BLE001
            with open(os.path.join(out, fname), "w", encoding="utf-8") as fh:
                fh.write(f"[error] {e}\n")
    log(f"minimal snapshot written to {out}")


def main() -> int:
    ap = argparse.ArgumentParser(description="IR triage orchestrator + Velociraptor abuse check")
    ap.add_argument("--os", choices=["auto", "windows", "linux", "macos"], default="auto")
    ap.add_argument("--out", default="./evidence", help="evidence output dir (use an off-host path)")
    ap.add_argument("--velociraptor-collector", action="store_true",
                    help="build a Velociraptor offline collector (Windows)")
    ap.add_argument("--vr-config", help="Velociraptor server config for collector build")
    ap.add_argument("--vr-bin"); ap.add_argument("--kape-bin")
    ap.add_argument("--uac-bin"); ap.add_argument("--catscale-bin")
    ap.add_argument("--check-velociraptor", action="store_true",
                    help="only run CVE-2025-6264 / persistence verification")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if args.check_velociraptor:
        res = check_velociraptor()
        print(json.dumps(res, indent=2))
        return 2 if res.get("vulnerable") else 0

    target = args.os
    if target == "auto":
        s = platform.system().lower()
        target = "windows" if s.startswith("win") else "macos" if s == "darwin" else "linux"

    os.makedirs(args.out, exist_ok=True)
    log(f"OS={target}  out={os.path.abspath(args.out)}  dry_run={args.dry_run}")
    log("REMINDER: acquire RAM FIRST (winpmem/AVML/LiME) before this triage on a live host.")

    if target == "windows":
        collect_windows(args)
    else:
        collect_unix(args)

    # Always co-run the suspect-tooling check during triage.
    log("Running Velociraptor abuse verification (CVE-2025-6264) ...")
    print(json.dumps(check_velociraptor(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
