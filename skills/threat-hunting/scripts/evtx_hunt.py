#!/usr/bin/env python3
"""
evtx_hunt.py - Offline Windows EVTX threat-hunting analytics (no SIEM required).

Parses Sysmon Operational / Security / PowerShell EVTX files and runs a set of
behavior analytics mapped to MITRE ATT&CK:
    - LSASS credential-access handle requests          (T1003.001)
    - AMSI/ETW in-memory patch indicators (ScriptBlock) (T1562.001/.002)
    - LOLBin download / proxy execution                 (T1218 / T1105)
    - Suspicious parent->child process trees            (T1059 / T1566)
    - Suspicious service install (non-system path)       (T1543.003 / T1021.002)
    - C2 named-pipe patterns                             (T1071 / T1559)
    - Log clears / Sysmon stop (visibility gap)          (T1070 / T1562.001)

USAGE:
    python3 evtx_hunt.py /path/to/EVTX_dir [--json findings.json] [--min-severity medium]
    python3 evtx_hunt.py Microsoft-Windows-Sysmon%4Operational.evtx Security.evtx

DEPENDENCIES:
    pip install python-evtx        # Willi Ballenthin's Evtx parser (pure python)
    pip install defusedxml         # hardened XML parsing (XXE / billion-laughs safe)

This is a defensive DFIR/hunting tool. Authorized use only.
"""
import argparse
import json
import re
import sys
from pathlib import Path

# Parse event XML with defusedxml to block XXE / entity-expansion attacks in
# attacker-influenced log data; fall back to a hardened stdlib parser if absent.
try:
    from defusedxml.ElementTree import fromstring as _fromstring
except ImportError:  # pragma: no cover - defusedxml strongly recommended
    from xml.etree.ElementTree import XMLParser
    from xml.etree import ElementTree as _ET

    def _fromstring(data):
        parser = XMLParser()
        # Disable entity resolution to mitigate XXE / billion-laughs on stdlib.
        try:
            parser.parser.DefaultHandler = lambda *_a, **_k: None
            parser.entity = {}
        except Exception:  # noqa: BLE001
            pass
        return _ET.fromstring(data, parser=parser)
from xml.etree import ElementTree as ET

try:
    from Evtx.Evtx import Evtx
except ImportError:
    sys.exit("Install python-evtx: pip install python-evtx")

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

LOLBINS = {"certutil.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe", "msiexec.exe",
           "wmic.exe", "cmstp.exe", "msxsl.exe", "bitsadmin.exe", "curl.exe",
           "installutil.exe", "regasm.exe", "regsvcs.exe"}
LOLBIN_FLAGS = ("http", "ftp", "\\\\", "-urlcache", "-decode", "scrobj.dll", "/i:http",
                "javascript:", "DownloadString", "DownloadFile")
LSASS_MASKS = {"0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff", "0x1f0fff", "0x1f1fff"}
AMSI_ETW = ("amsiscanbuffer", "amsiinitfailed", "amsiutils", "etweventwrite", "nttraceevent")
PATCH_MECH = ("virtualprotect", "marshal.copy", "getprocaddress", "writeprocessmemory")
PIPE_RE = re.compile(r"\\(MSSE-|msagent_|postex_\d|status_\w+|mojo\.\d+\.\d+\.\d+|sliver-|interactsh)",
                     re.IGNORECASE)
SUSPICIOUS_PARENTS = {
    "winword.exe": {"cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe"},
    "excel.exe": {"cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe"},
    "outlook.exe": {"powershell.exe", "cmd.exe", "mshta.exe", "wscript.exe"},
    "w3wp.exe": {"cmd.exe", "powershell.exe"},
    "sqlservr.exe": {"cmd.exe", "powershell.exe"},
    "wmiprvse.exe": {"powershell.exe", "cmd.exe"},
}
SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def ev_to_dict(xml_bytes):
    """Flatten one Event XML record into {EventID, Channel, **EventData}."""
    try:
        root = _fromstring(xml_bytes)
    except ET.ParseError:
        return None
    except Exception:  # noqa: BLE001 - defusedxml raises on malicious entities
        return None
    out = {}
    sys_el = root.find("e:System", NS)
    if sys_el is not None:
        eid = sys_el.find("e:EventID", NS)
        chan = sys_el.find("e:Channel", NS)
        tc = sys_el.find("e:TimeCreated", NS)
        out["EventID"] = (eid.text or "").strip() if eid is not None else ""
        out["Channel"] = chan.text if chan is not None else ""
        out["Time"] = tc.get("SystemTime") if tc is not None else ""
    for data in root.iter("{%s}Data" % NS["e"]):
        n = data.get("Name")
        if n:
            out[n] = (data.text or "")
    return out


def basename_lower(p: str) -> str:
    return re.split(r"[\\/]", p.strip())[-1].lower() if p else ""


def analyze(ev, findings):
    eid = ev.get("EventID", "")
    chan = (ev.get("Channel") or "").lower()
    t = ev.get("Time", "")

    def add(sev, attck, title, detail):
        findings.append({"severity": sev, "attck": attck, "title": title,
                         "time": t, "detail": detail})

    # Sysmon EID 1: process creation -> LOLBins + tree anomalies
    if eid == "1":
        img = basename_lower(ev.get("Image", ""))
        pimg = basename_lower(ev.get("ParentImage", ""))
        cmd = (ev.get("CommandLine") or "")
        cl = cmd.lower()
        if img in LOLBINS and any(f.lower() in cl for f in LOLBIN_FLAGS):
            add("high", "T1218/T1105", "LOLBin download/proxy execution",
                f"{img} :: {cmd[:300]}")
        if pimg in SUSPICIOUS_PARENTS and img in SUSPICIOUS_PARENTS[pimg]:
            add("high", "T1059/T1566", "Suspicious parent->child process tree",
                f"{pimg} -> {img} :: {cmd[:200]}")
        if img == "powershell.exe" and ("-enc" in cl or "-encodedcommand" in cl or
                                        "frombase64string" in cl):
            add("medium", "T1059.001", "Encoded PowerShell execution", cmd[:300])

    # Sysmon EID 10: process access -> LSASS handle
    elif eid == "10":
        tgt = basename_lower(ev.get("TargetImage", ""))
        src = ev.get("SourceImage", "")
        ga = (ev.get("GrantedAccess") or "").lower()
        if tgt == "lsass.exe" and any(m in ga for m in LSASS_MASKS):
            if not re.search(r"(?i)\\(System32|Windows Defender|Microsoft Defender)\\", src):
                add("high", "T1003.001", "LSASS credential-access handle",
                    f"{src} -> lsass.exe GrantedAccess={ev.get('GrantedAccess')}")

    # Sysmon EID 17/18: pipe create/connect -> C2 named pipe
    elif eid in ("17", "18"):
        pn = ev.get("PipeName", "")
        if pn and PIPE_RE.search(pn):
            add("high", "T1071/T1559", "C2-pattern named pipe",
                f"PipeName={pn} Image={ev.get('Image','')}")

    # Sysmon EID 25: process tampering
    elif eid == "25":
        add("high", "T1055", "Process tampering (hollowing/herpaderping)",
            f"Image={ev.get('Image','')} Type={ev.get('Type','')}")

    # PowerShell ScriptBlock (4104) -> AMSI/ETW patch
    elif eid == "4104":
        sb = (ev.get("ScriptBlockText") or "").lower()
        if any(a in sb for a in AMSI_ETW) and any(m in sb for m in PATCH_MECH):
            add("high", "T1562.001/.002", "AMSI/ETW in-memory patch indicators",
                "ScriptBlock contains AMSI/ETW symbol + memory-patch primitive")

    # Security 7045 / System 7045: service install w/ non-system path
    elif eid == "7045":
        svcpath = (ev.get("ServiceFileName") or ev.get("ImagePath") or "")
        if svcpath and not re.search(r"(?i)c:\\(windows|program files)", svcpath):
            add("medium", "T1543.003/T1021.002", "Service installed with non-system binary",
                f"{ev.get('ServiceName','?')} :: {svcpath[:250]}")

    # Security 1102: audit log cleared (visibility gap)
    elif eid == "1102":
        add("high", "T1070.001", "Security event log cleared", "Audit log cleared (1102)")

    # System 7036/7034 Sysmon stop
    elif eid in ("7034", "7036"):
        svc = (ev.get("param1") or ev.get("ServiceName") or "")
        if "sysmon" in svc.lower() and ("stop" in (ev.get("param2", "")).lower() or eid == "7034"):
            add("high", "T1562.001", "Sysmon service stopped (visibility gap)", svc)


def main():
    ap = argparse.ArgumentParser(description="Offline EVTX threat-hunting analytics")
    ap.add_argument("paths", nargs="+", help="EVTX files or a directory of EVTX files")
    ap.add_argument("--json", help="write findings to JSON file")
    ap.add_argument("--min-severity", default="low",
                    choices=list(SEV_ORDER), help="minimum severity to report")
    args = ap.parse_args()

    targets = []
    for p in args.paths:
        pp = Path(p)
        if pp.is_dir():
            targets += sorted(pp.rglob("*.evtx"))
        elif pp.exists():
            targets.append(pp)
    if not targets:
        sys.exit("No EVTX files found.")

    findings = []
    for f in targets:
        print(f"[*] Parsing {f}", file=sys.stderr)
        try:
            with Evtx(str(f)) as log:
                for rec in log.records():
                    ev = ev_to_dict(rec.xml())
                    if ev:
                        analyze(ev, findings)
        except Exception as e:  # noqa: BLE001 - keep triaging remaining files
            print(f"[!] {f}: {e}", file=sys.stderr)

    minsev = SEV_ORDER[args.min_severity]
    findings = [x for x in findings if SEV_ORDER[x["severity"]] >= minsev]
    findings.sort(key=lambda x: SEV_ORDER[x["severity"]], reverse=True)

    for x in findings:
        print(f"[{x['severity'].upper():8}] {x['attck']:18} {x['title']}")
        print(f"           {x['time']}  {x['detail']}")

    print(f"\n[=] {len(findings)} finding(s) at >= {args.min_severity}", file=sys.stderr)
    if args.json:
        Path(args.json).write_text(json.dumps(findings, indent=2), encoding="utf-8")
        print(f"[+] Wrote {args.json}", file=sys.stderr)


if __name__ == "__main__":
    main()
