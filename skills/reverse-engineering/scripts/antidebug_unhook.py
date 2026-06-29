#!/usr/bin/env python3
"""
antidebug_unhook.py - locate anti-debug / anti-VM primitives in a binary and emit
per-hit bypass guidance, plus generate a ready-to-load Frida neutralizer and an
LD_PRELOAD ptrace stub.

Static scan walks imports (lief/pefile) and disassembles the .text section
(capstone) looking for the canonical instruction/timing tells.

Usage:
    python3 antidebug_unhook.py --scan ./sample
    python3 antidebug_unhook.py --scan ./sample --emit-frida out/ad.js --emit-preload out/noptrace.c

Dependencies (optional, graceful degradation):
    pip install lief capstone pefile
"""
import argparse
import os
import re
import sys

try:
    import lief
except ImportError:
    lief = None
try:
    import capstone
except ImportError:
    capstone = None

# import-name -> (technique, bypass)
IMPORT_TELLS = {
    "IsDebuggerPresent": ("PEB.BeingDebugged read", "hook -> 0 / zero PEB+0x02 (ScyllaHide)"),
    "CheckRemoteDebuggerPresent": ("debug-port query", "hook -> 0"),
    "NtQueryInformationProcess": ("ProcessDebugPort/Flags", "hook -> return 0 / NULL port"),
    "NtSetInformationThread": ("ThreadHideFromDebugger(0x11)", "hook NtSetInformationThread or pass class 0"),
    "GetThreadContext": ("HW breakpoint DR0-3 read", "zero Dr0..Dr3 in returned CONTEXT"),
    "NtQuerySystemInformation": ("kernel-debugger/module enum", "strip entries (sice.sys/syser.sys)"),
    "OutputDebugStringA": ("OutputDebugString anti-debug", "ignore / spoof GetLastError"),
    "NtClose": ("NtClose(invalid handle) exception", "catch/ignore EXCEPTION_INVALID_HANDLE"),
    "ptrace": ("ptrace(PTRACE_TRACEME)", "LD_PRELOAD stub -> 0, or NOP the call"),
    "GetTickCount": ("timing anti-debug", "spoof monotonic deltas (ScyllaHide)"),
    "QueryPerformanceCounter": ("timing anti-debug", "spoof monotonic deltas"),
}

# raw byte patterns in .text -> (technique, bypass)
ASM_TELLS = [
    (b"\x0f\x31", "rdtsc (timing)", "patch CMP after rdtsc / single-step with HW bp"),
    (b"\xcd\x2d", "INT 2D anti-debug", "single-step over, fix EIP/EFLAGS"),
    (b"\xf1", "ICEBP/INT1", "single-step over (note: 0xF1 also appears in data)"),
    (b"\x0f\xa2", "CPUID (hypervisor bit / brand check)", "patch CPUID result (ScyllaHide/TitanHide)"),
]


FRIDA_TEMPLATE = """// auto-generated anti-debug neutralizer (frida -p <pid> -l this.js)
'use strict';
const k32 = Process.platform === 'windows' ? 'kernel32.dll' : null;
if (k32) {
  const idp = Module.findExportByName(k32, 'IsDebuggerPresent');
  if (idp) Interceptor.replace(idp, new NativeCallback(() => 0, 'int', []));
}
const ptrace = Module.findExportByName(null, 'ptrace');
if (ptrace) Interceptor.replace(ptrace,
  new NativeCallback(() => 0, 'long', ['int','int','pointer','pointer']));
console.log('[ad] neutralizer loaded');
"""

PRELOAD_TEMPLATE = """/* gcc -shared -fPIC -o noptrace.so noptrace.c
 * LD_PRELOAD=./noptrace.so ./sample
 */
#define _GNU_SOURCE
#include <sys/ptrace.h>
long ptrace(int request, ...) {
    /* PTRACE_TRACEME == 0; always report success and never actually trace. */
    return 0;
}
"""


def scan(path):
    findings = []
    binary = lief.parse(path) if lief else None

    # imports
    imports = []
    if binary is not None:
        try:
            if binary.format == lief.EXE_FORMATS.PE:
                for imp in binary.imports:
                    for e in imp.entries:
                        if e.name:
                            imports.append(e.name)
            else:
                for f in binary.imported_functions:
                    imports.append(getattr(f, "name", str(f)))
        except Exception:
            pass
    for name in imports:
        base = name.lstrip("_")
        for tell, (tech, fix) in IMPORT_TELLS.items():
            if base.startswith(tell):
                findings.append({"kind": "import", "name": name,
                                 "technique": tech, "bypass": fix})

    # .text disassembly / byte search
    text = b""
    text_addr = 0
    if binary is not None:
        try:
            sec = binary.get_section(".text")
            if sec:
                text = bytes(sec.content)
                text_addr = sec.virtual_address
        except Exception:
            pass
    if not text:
        with open(path, "rb") as f:
            text = f.read()

    for pat, tech, fix in ASM_TELLS:
        start = 0
        while True:
            idx = text.find(pat, start)
            if idx < 0:
                break
            findings.append({"kind": "asm", "offset": hex(text_addr + idx),
                             "technique": tech, "bypass": fix})
            start = idx + 1

    return findings, imports


def main():
    ap = argparse.ArgumentParser(description="Anti-debug primitive scanner + bypass emitter")
    ap.add_argument("--scan", required=True, metavar="BINARY")
    ap.add_argument("--emit-frida", metavar="PATH")
    ap.add_argument("--emit-preload", metavar="PATH")
    args = ap.parse_args()

    findings, imports = scan(args.scan)
    print(f"[+] {args.scan}: {len(findings)} anti-analysis tell(s)\n")
    for f in findings:
        loc = f.get("name") or f.get("offset")
        print(f"  [{f['kind']:6}] {loc:<28} {f['technique']}")
        print(f"           -> bypass: {f['bypass']}")
    if not findings:
        print("  (no obvious static anti-debug tells; sample may use custom/obfuscated checks)")

    if args.emit_frida:
        os.makedirs(os.path.dirname(args.emit_frida) or ".", exist_ok=True)
        with open(args.emit_frida, "w") as fp:
            fp.write(FRIDA_TEMPLATE)
        print(f"\n[+] frida neutralizer -> {args.emit_frida}")
    if args.emit_preload:
        os.makedirs(os.path.dirname(args.emit_preload) or ".", exist_ok=True)
        with open(args.emit_preload, "w") as fp:
            fp.write(PRELOAD_TEMPLATE)
        print(f"[+] LD_PRELOAD ptrace stub -> {args.emit_preload}")
        print("    build: gcc -shared -fPIC -o noptrace.so " + args.emit_preload)


if __name__ == "__main__":
    main()
