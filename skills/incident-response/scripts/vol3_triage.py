#!/usr/bin/env python3
"""
vol3_triage.py - Volatility 3 batch triage runner with injection / rootkit / credential heuristics.

Drives a curated set of Volatility 3 plugins against a memory image, captures JSON output, and
applies simple analyst heuristics:
  * pslist-vs-psscan diff -> hidden (DKOM-unlinked) processes
  * malfind / hollowprocesses presence -> injected / hollowed code
  * suspicious parent->child (Office->cmd/powershell, reparented svchost)
  * credential-relevant plugins (lsadump/hashdump) flagged for offline follow-up

Usage:
  python3 vol3_triage.py -f mem.raw  --os windows --hunt-injection --dump-suspect -o ./vol_out
  python3 vol3_triage.py -f mem.lime --os linux                                   -o ./vol_out
  python3 vol3_triage.py -f mem.raw  --os windows --vol "python3 -m volatility3.cli"

Dependencies: Volatility 3 (`vol3`/`vol` on PATH, or pass --vol). For Linux images you must have a
  matching symbol pack installed (build with dwarf2json; see references/memory-forensics.md).
Notes: read-only against the dump. Dumped processes/DLLs may contain credentials/PII -> handle per
  case policy. Run on an analysis workstation, not the suspect host.
"""
import argparse
import json
import os
import shlex
import subprocess
import sys

WINDOWS_PLUGINS = [
    "windows.info", "windows.pslist", "windows.psscan", "windows.pstree",
    "windows.cmdline", "windows.netscan", "windows.svcscan",
    "windows.registry.printkey",  # Run key handled specially below
]
WINDOWS_INJECTION = ["windows.malfind", "windows.hollowprocesses", "windows.ldrmodules"]
WINDOWS_ROOTKIT = ["windows.ssdt", "windows.callbacks", "windows.driverirp", "windows.modscan"]
WINDOWS_CREDS = ["windows.lsadump", "windows.hashdump"]

LINUX_PLUGINS = ["linux.pslist", "linux.pstree", "linux.psscan", "linux.bash",
                 "linux.lsof", "linux.sockstat"]
LINUX_ROOTKIT = ["linux.check_syscall", "linux.check_modules", "linux.hidden_modules",
                 "linux.ebpf", "linux.tracing.ftrace"]

SUSP_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "mshta.exe"}
SUSP_CHILDREN = {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "rundll32.exe"}


def run_plugin(vol: str, image: str, plugin: str, extra=None, dump_dir=None):
    cmd = shlex.split(vol) + ["-q", "-r", "json", "-f", image, plugin]
    if dump_dir:
        cmd += ["-o", dump_dir]
    if extra:
        cmd += extra
    print("[*] " + " ".join(cmd), file=sys.stderr)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    except FileNotFoundError:
        print(f"[!] volatility not found: {vol}", file=sys.stderr)
        return None
    except subprocess.TimeoutExpired:
        print(f"[!] {plugin} timed out", file=sys.stderr)
        return None
    if p.returncode != 0:
        print(f"[!] {plugin} rc={p.returncode}: {p.stderr.strip()[:300]}", file=sys.stderr)
    try:
        return json.loads(p.stdout) if p.stdout.strip() else []
    except json.JSONDecodeError:
        return {"_raw": p.stdout}


def name_of(row, *keys):
    for k in keys:
        if k in row and row[k] not in (None, ""):
            return str(row[k])
    return ""


def analyze_windows(results):
    findings = []
    pslist = {str(r.get("PID")): name_of(r, "ImageFileName", "Name")
              for r in results.get("windows.pslist", []) if isinstance(r, dict)}
    psscan = {str(r.get("PID")): name_of(r, "ImageFileName", "Name")
              for r in results.get("windows.psscan", []) if isinstance(r, dict)}
    hidden = [(pid, n) for pid, n in psscan.items() if pid not in pslist]
    for pid, n in hidden:
        findings.append({"sev": "HIGH", "type": "hidden_process_DKOM",
                         "detail": f"PID {pid} ({n}) in psscan but not pslist"})

    # parent/child anomalies from pstree (flat scan of rows)
    for r in results.get("windows.pslist", []):
        if not isinstance(r, dict):
            continue
        child = name_of(r, "ImageFileName", "Name").lower()
        ppid = str(r.get("PPID"))
        parent = pslist.get(ppid, "").lower()
        if parent in SUSP_PARENTS and child in SUSP_CHILDREN:
            findings.append({"sev": "HIGH", "type": "suspicious_parent_child",
                             "detail": f"{parent} -> {child} (PID {r.get('PID')})"})

    if results.get("windows.malfind"):
        n = len(results["windows.malfind"]) if isinstance(results["windows.malfind"], list) else 1
        findings.append({"sev": "HIGH", "type": "code_injection",
                         "detail": f"malfind reported {n} executable private region(s)"})
    if results.get("windows.hollowprocesses"):
        findings.append({"sev": "HIGH", "type": "process_hollowing",
                         "detail": "hollowprocesses returned image/section mismatch(es)"})
    if results.get("windows.lsadump") or results.get("windows.hashdump"):
        findings.append({"sev": "INFO", "type": "credentials_present",
                         "detail": "secrets extracted -> run pypykatz on a dumped lsass for plaintext"})
    return findings


def analyze_linux(results):
    findings = []
    if results.get("linux.hidden_modules"):
        findings.append({"sev": "HIGH", "type": "hidden_kernel_module",
                         "detail": "linux.hidden_modules carved unlinked module(s)"})
    sc = results.get("linux.check_syscall", [])
    hooked = [r for r in sc if isinstance(r, dict) and str(r.get("Hooked", "")).lower()
              in ("true", "yes", "1")]
    if hooked:
        findings.append({"sev": "HIGH", "type": "syscall_hook",
                         "detail": f"{len(hooked)} syscall table entr(y/ies) hooked"})
    ebpf = results.get("linux.ebpf", [])
    if ebpf:
        findings.append({"sev": "MEDIUM", "type": "ebpf_programs_loaded",
                         "detail": f"{len(ebpf) if isinstance(ebpf, list) else 1} eBPF prog(s) "
                                   f"present -> inspect for getdents/sys_bpf/xdp hooks (LinkPro)"})
    return findings


def main() -> int:
    ap = argparse.ArgumentParser(description="Volatility 3 batch triage")
    ap.add_argument("-f", "--file", required=True, help="memory image")
    ap.add_argument("--os", choices=["windows", "linux"], required=True)
    ap.add_argument("--vol", default=os.environ.get("VOL3", "vol3"),
                    help="volatility command (default: vol3; e.g. 'python3 -m volatility3.cli')")
    ap.add_argument("--hunt-injection", action="store_true")
    ap.add_argument("--dump-suspect", action="store_true",
                    help="pass -o to malfind so injected regions are dumped")
    ap.add_argument("--creds", action="store_true", help="also run lsadump/hashdump (Windows)")
    ap.add_argument("-o", "--out", default="./vol_out")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    results = {}

    if args.os == "windows":
        plugins = list(WINDOWS_PLUGINS)
        if args.hunt_injection:
            plugins += WINDOWS_INJECTION + WINDOWS_ROOTKIT
        if args.creds:
            plugins += WINDOWS_CREDS
    else:
        plugins = LINUX_PLUGINS + LINUX_ROOTKIT

    for plugin in plugins:
        extra = dump_dir = None
        if plugin == "windows.registry.printkey":
            extra = ["--key", r"Software\Microsoft\Windows\CurrentVersion\Run"]
        if plugin == "windows.malfind" and args.dump_suspect:
            dump_dir = os.path.join(args.out, "dumped")
            os.makedirs(dump_dir, exist_ok=True)
        data = run_plugin(args.vol, args.file, plugin, extra=extra, dump_dir=dump_dir)
        results[plugin] = data
        with open(os.path.join(args.out, plugin.replace(".", "_") + ".json"), "w",
                  encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)

    findings = analyze_windows(results) if args.os == "windows" else analyze_linux(results)
    report = {"image": args.file, "os": args.os, "findings": findings}
    with open(os.path.join(args.out, "_findings.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    print("\n=== TRIAGE FINDINGS ===")
    if not findings:
        print("(no heuristic hits — review raw JSON manually; absence != clean)")
    for f in findings:
        print(f"[{f['sev']}] {f['type']}: {f['detail']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
