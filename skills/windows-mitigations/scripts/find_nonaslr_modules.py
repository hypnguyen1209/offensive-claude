#!/usr/bin/env python3
"""
find_nonaslr_modules.py - Identify PE modules (DLL/EXE) that are NOT ASLR-compatible.

A module without IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (0x0040) loads at its fixed preferred
base unless Mandatory ASLR / ForceRelocateImages overrides it. Such modules are a reliable ROP
gadget source even without an information leak. This tool parses the PE optional header
DllCharacteristics field and reports per-module ASLR / HEASLR / CFG / CET posture.

Usage:
    python find_nonaslr_modules.py "C:\\Program Files\\Target\\*.dll"
    python find_nonaslr_modules.py file1.dll file2.exe ...
    python find_nonaslr_modules.py --dir "C:\\Windows\\System32" --ext .dll

Dependencies: standard library only (struct, glob, argparse). No pefile required.
For authorized engagement use only.
"""
import argparse
import glob
import struct
import sys

# DllCharacteristics flags
DYNAMIC_BASE        = 0x0040  # ASLR
HIGH_ENTROPY_VA     = 0x0020  # HEASLR (64-bit)
NX_COMPAT           = 0x0100  # DEP
GUARD_CF            = 0x4000  # CFG present
FORCE_INTEGRITY     = 0x0080  # signature enforced

# IMAGE_DLLCHARACTERISTICS_EX (extended, in load config) CET flag
IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT = 0x0001


def parse_pe(path):
    """Return dict of PE characteristics, or None if not a PE."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        return {"error": str(e)}

    if data[:2] != b"MZ" or len(data) < 0x40:
        return None
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 0x18 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return None

    coff = e_lfanew + 4
    machine = struct.unpack_from("<H", data, coff)[0]
    opt = coff + 20  # COFF header is 20 bytes
    magic = struct.unpack_from("<H", data, opt)[0]
    is_pe32_plus = (magic == 0x20B)

    # DllCharacteristics offset within optional header: 0x46 for both PE32 and PE32+
    dllchar = struct.unpack_from("<H", data, opt + 0x46)[0]

    return {
        "machine": "x64" if machine == 0x8664 else ("x86" if machine == 0x14C else hex(machine)),
        "bits": 64 if is_pe32_plus else 32,
        "aslr":   bool(dllchar & DYNAMIC_BASE),
        "heaslr": bool(dllchar & HIGH_ENTROPY_VA),
        "dep":    bool(dllchar & NX_COMPAT),
        "cfg":    bool(dllchar & GUARD_CF),
        "forceintegrity": bool(dllchar & FORCE_INTEGRITY),
        "dllchar_raw": dllchar,
    }


def collect(args):
    files = []
    if args.dir:
        files += glob.glob(f"{args.dir}/**/*{args.ext}", recursive=True)
    for pat in args.targets:
        files += glob.glob(pat) if any(c in pat for c in "*?[") else [pat]
    # de-dup, preserve order
    seen, out = set(), []
    for f in files:
        if f not in seen:
            seen.add(f); out.append(f)
    return out


def main():
    ap = argparse.ArgumentParser(description="Find non-ASLR PE modules (ROP gadget sources).")
    ap.add_argument("targets", nargs="*", help="PE files or glob patterns")
    ap.add_argument("--dir", help="recurse a directory")
    ap.add_argument("--ext", default=".dll", help="extension filter for --dir (default .dll)")
    ap.add_argument("--only-weak", action="store_true", help="only print modules missing ASLR")
    args = ap.parse_args()

    files = collect(args)
    if not files:
        print("No files matched.", file=sys.stderr)
        sys.exit(1)

    hdr = f"{'ASLR':5} {'HEASLR':6} {'DEP':4} {'CFG':4} {'BITS':4}  PATH"
    print(hdr)
    print("-" * len(hdr))
    weak = []
    for path in files:
        info = parse_pe(path)
        if info is None:
            continue
        if "error" in info:
            print(f"  [!] {path}: {info['error']}", file=sys.stderr)
            continue
        if args.only_weak and info["aslr"]:
            continue
        if not info["aslr"]:
            weak.append(path)
        print("{aslr:<5} {he:<6} {dep:<4} {cfg:<4} {bits:<4}  {p}".format(
            aslr="NO" if not info["aslr"] else "yes",
            he="NO" if not info["heaslr"] else "yes",
            dep="NO" if not info["dep"] else "yes",
            cfg="NO" if not info["cfg"] else "yes",
            bits=info["bits"], p=path))

    print()
    if weak:
        print(f"[+] {len(weak)} fixed-base (non-ASLR) module(s) - usable as ROP source without a leak:")
        for w in weak:
            print(f"    {w}")
    else:
        print("[-] All scanned modules are ASLR-compatible; an info leak is required.")


if __name__ == "__main__":
    main()
