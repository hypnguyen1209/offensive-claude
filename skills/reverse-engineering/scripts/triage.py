#!/usr/bin/env python3
"""
triage.py - One-shot static triage of an unknown binary (ELF / PE / Mach-O).

Outputs JSON: format, arch/bits/endian, exploit mitigations, per-section Shannon
entropy + packer guess, top strings, imports/exports, and capability tags derived
from suspicious imports (crypto / network / process-injection / anti-debug).

Optionally drives Ghidra 11.4 analyzeHeadless to decompile every function to C.

Usage:
    python3 triage.py ./sample -o out/triage.json
    python3 triage.py ./sample --decompile --ghidra /opt/ghidra_11.4.3_PUBLIC -o out/
    python3 triage.py ./sample.exe --strings-min 6 -o out/triage.json

Dependencies (all optional; the script degrades gracefully if missing):
    pip install lief pefile capstone
    Ghidra (for --decompile) with $GHIDRA_HOME/support/analyzeHeadless
Pure-stdlib fallbacks cover format detection, entropy and strings if lief/pefile absent.
"""
import argparse
import json
import math
import os
import re
import struct
import subprocess
import sys

try:
    import lief
except ImportError:
    lief = None
try:
    import pefile
except ImportError:
    pefile = None

# import-name -> capability tag
CAP_MAP = {
    r"(VirtualAlloc|WriteProcessMemory|CreateRemoteThread|NtMapViewOfSection|QueueUserAPC)": "process-injection",
    r"(socket|connect|send|recv|WSAStartup|InternetOpen|WinHttp|curl_easy)": "network",
    r"(CryptEncrypt|BCrypt|EVP_|AES_|RC4|MD5|SHA256)": "crypto",
    r"(IsDebuggerPresent|CheckRemoteDebugger|NtQueryInformationProcess|ptrace|NtSetInformationThread)": "anti-debug",
    r"(GetTickCount|QueryPerformanceCounter|rdtsc)": "timing/anti-vm",
    r"(RegSetValue|RegCreateKey|CreateService|schtasks)": "persistence",
    r"(LoadLibrary|GetProcAddress|LdrLoadDll|dlopen|dlsym)": "dynamic-api-resolution",
    r"(CreateFile|WriteFile|fopen|unlink|DeleteFile)": "filesystem",
}


def shannon(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c)


def detect_format(data: bytes) -> str:
    if data[:4] == b"\x7fELF":
        return "ELF"
    if data[:2] == b"MZ":
        return "PE"
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                    b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "Mach-O"
    return "unknown"


def ascii_strings(data: bytes, minlen: int):
    out, cur = [], bytearray()
    for b in data:
        if 0x20 <= b < 0x7f:
            cur.append(b)
        else:
            if len(cur) >= minlen:
                out.append(cur.decode("ascii", "ignore"))
            cur = bytearray()
    if len(cur) >= minlen:
        out.append(cur.decode("ascii", "ignore"))
    return out


def mitigations_pe(path: str) -> dict:
    m = {}
    if pefile:
        pe = pefile.PE(path, fast_load=True)
        dc = pe.OPTIONAL_HEADER.DllCharacteristics
        m["ASLR_DYNAMIC_BASE"] = bool(dc & 0x0040)
        m["HIGH_ENTROPY_VA"] = bool(dc & 0x0020)
        m["NX_DEP"] = bool(dc & 0x0100)
        m["CFG"] = bool(dc & 0x4000)
        m["FORCE_INTEGRITY"] = bool(dc & 0x0080)
        m["has_security_dir"] = bool(
            pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress)  # Authenticode
        pe.close()
    return m


def mitigations_elf(binary) -> dict:
    m = {"NX": True, "PIE": False, "RELRO": "none", "CANARY": False}
    try:
        m["PIE"] = binary.header.file_type == lief.ELF.E_TYPE.DYNAMIC
        seg_types = {s.type for s in binary.segments}
        if lief.ELF.SEGMENT_TYPES.GNU_STACK in seg_types:
            gs = next(s for s in binary.segments
                      if s.type == lief.ELF.SEGMENT_TYPES.GNU_STACK)
            m["NX"] = not (gs.flags & 0x1)  # PF_X
        if lief.ELF.SEGMENT_TYPES.GNU_RELRO in seg_types:
            m["RELRO"] = "full" if any(
                d.tag == lief.ELF.DYNAMIC_TAGS.BIND_NOW for d in binary.dynamic_entries
            ) else "partial"
        m["CANARY"] = any("__stack_chk_fail" in (s.name or "")
                          for s in binary.symbols)
    except Exception:
        pass
    return m


def collect_imports(binary, fmt, path):
    imps = []
    if lief and binary is not None:
        try:
            if fmt == "PE":
                for imp in binary.imports:
                    for e in imp.entries:
                        if e.name:
                            imps.append(e.name)
            else:
                for f in binary.imported_functions:
                    imps.append(getattr(f, "name", str(f)))
        except Exception:
            pass
    elif pefile and fmt == "PE":
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            for imp in entry.imports:
                if imp.name:
                    imps.append(imp.name.decode(errors="ignore"))
        pe.close()
    return sorted(set(imps))


def capabilities(imports):
    joined = "\n".join(imports)
    tags = set()
    for pat, tag in CAP_MAP.items():
        if re.search(pat, joined):
            tags.add(tag)
    return sorted(tags)


def run_ghidra(path, ghidra_home, out_dir):
    script_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ghidra")
    headless = os.path.join(ghidra_home, "support",
                            "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
    if not os.path.exists(headless):
        return f"analyzeHeadless not found at {headless}"
    proj = os.path.join(out_dir, "ghidra_proj")
    os.makedirs(proj, exist_ok=True)
    cmd = [headless, proj, "triage", "-import", path, "-overwrite",
           "-postScript", "DecompileToC.java", "-scriptPath", script_dir]
    try:
        subprocess.run(cmd, check=True, timeout=1800)
        return "ok"
    except Exception as e:  # noqa: BLE001
        return f"ghidra error: {e}"


def main():
    ap = argparse.ArgumentParser(description="Static binary triage")
    ap.add_argument("binary")
    ap.add_argument("-o", "--out", default="triage.json",
                    help="JSON file, or directory when --decompile")
    ap.add_argument("--strings-min", type=int, default=8)
    ap.add_argument("--top-strings", type=int, default=60)
    ap.add_argument("--decompile", action="store_true")
    ap.add_argument("--ghidra", default=os.environ.get("GHIDRA_HOME", ""))
    args = ap.parse_args()

    with open(args.binary, "rb") as f:
        data = f.read()

    fmt = detect_format(data)
    report = {"path": os.path.abspath(args.binary), "size": len(data),
              "format": fmt, "overall_entropy": round(shannon(data), 4)}

    binary = lief.parse(args.binary) if lief else None
    if binary is not None:
        try:
            report["arch"] = str(binary.header.machine_type)
            report["entrypoint"] = hex(binary.entrypoint)
        except Exception:
            pass

    # mitigations
    if fmt == "PE":
        report["mitigations"] = mitigations_pe(args.binary)
    elif fmt == "ELF" and binary is not None:
        report["mitigations"] = mitigations_elf(binary)

    # per-section entropy + packer guess
    sections, max_ent = [], 0.0
    if binary is not None:
        for s in getattr(binary, "sections", []):
            try:
                sd = bytes(s.content)
            except Exception:
                sd = b""
            e = shannon(sd)
            max_ent = max(max_ent, e)
            sections.append({"name": s.name, "size": len(sd), "entropy": round(e, 4)})
    report["sections"] = sections
    names = " ".join(s["name"] for s in sections).lower()
    packer = None
    if "upx" in names:
        packer = "UPX"
    elif ".vmp" in names or "vmp0" in names:
        packer = "VMProtect"
    elif ".themida" in names or ".winlice" in names:
        packer = "Themida/WinLicense"
    elif max_ent > 7.2:
        packer = "likely-packed (high entropy)"
    report["packer_guess"] = packer

    # strings + imports + capabilities
    strs = ascii_strings(data, args.strings_min)
    interesting = [s for s in strs if re.search(
        r"(?i)(password|secret|key|flag|http|/bin/|cmd\.exe|\.dll|BEGIN .*PRIVATE)", s)]
    report["top_strings"] = (interesting + strs)[:args.top_strings]
    imports = collect_imports(binary, fmt, args.binary)
    report["imports_sample"] = imports[:120]
    report["capabilities"] = capabilities(imports)

    # output
    if args.decompile:
        out_dir = args.out if os.path.isdir(args.out) or not args.out.endswith(".json") else os.path.dirname(args.out) or "."
        os.makedirs(out_dir, exist_ok=True)
        if not args.ghidra:
            report["decompile"] = "skipped: pass --ghidra or set GHIDRA_HOME"
        else:
            report["decompile"] = run_ghidra(args.binary, args.ghidra, out_dir)
        json_path = os.path.join(out_dir, "triage.json")
    else:
        json_path = args.out
        os.makedirs(os.path.dirname(json_path) or ".", exist_ok=True)

    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)
    print(json.dumps({k: report[k] for k in
                      ("format", "arch", "packer_guess", "capabilities")
                      if k in report}, indent=2))
    print(f"[+] full report: {json_path}")


if __name__ == "__main__":
    main()
