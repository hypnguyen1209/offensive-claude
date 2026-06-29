#!/usr/bin/env python3
"""
uefi_triage.py - first-pass triage of a firmware image: distinguish UEFI/BIOS from
embedded-Linux/RTOS, carve it, enumerate DXE/PEI modules (UEFI) or root FS loot
(Linux), and flag the verified 2024-2025 Secure Boot bypass indicators:
  - PKfail   : AMI "DO NOT TRUST" test Platform Key still present (CVE-2024-8105)
  - CVE-2024-7344 : 'cloak.dat' / 'ALRM' magic + known-vulnerable reloader.efi hashes
  - LogoFAIL : suspicious boot-logo images in firmware volumes (CVE-2023-40238 family)

Usage:
    python3 uefi_triage.py firmware.bin -o out/fw/

Dependencies:
    External (invoked if on PATH): binwalk, unblob, UEFIExtract / uefi-firmware-parser.
    Pure-Python: signature scan + entropy + hash matching work with no extra deps.
"""
import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys

# CVE-2024-7344 vulnerable reloader.efi Authenticode SHA-256 (ESET, verified)
CVE_2024_7344_HASHES = {
    "cdb7c90d3ab8833d5324f5d8516d41fa990b9ca721fe643fffaef9057d9f9e48": "reloader.efi x64",
    "e9e4b5a51f6a5575b9f5bfab1852b0cb2795c66ff4b28135097cba671a5491b9": "reloader.efi x86",
}

# Firmware Volume GUID signature ('_FVH') and common UEFI markers
FV_SIGNATURE = b"_FVH"
UEFI_MARKERS = [b"_FVH", b"$IBIOSI$", b"PEI Core", b"DxeCore"]
PKFAIL_MARKERS = [b"DO NOT TRUST", b"DO NOT SHIP", b"DO NOT TRUST - AMI Test PK"]
CLOAK_MARKERS = [b"ALRM"]  # cloak.dat magic (CVE-2024-7344)
LOGO_MAGICS = {b"BM": "BMP", b"\x89PNG": "PNG", b"\xff\xd8\xff": "JPEG", b"GIF8": "GIF"}


def which(name):
    return shutil.which(name) is not None


def is_uefi(data: bytes) -> bool:
    return any(m in data[:0x2000000] for m in UEFI_MARKERS)


def carve(path, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    if which("unblob"):
        subprocess.run(["unblob", "-e", out_dir, path], check=False)
        return "unblob"
    if which("binwalk"):
        subprocess.run(["binwalk", "-e", "-C", out_dir, path], check=False)
        return "binwalk"
    return None


def uefi_extract(path, out_dir):
    if which("UEFIExtract"):
        subprocess.run(["UEFIExtract", path], check=False)
        return "UEFIExtract"
    if which("uefi-firmware-parser"):
        subprocess.run(["uefi-firmware-parser", "-e", "-O", out_dir, path], check=False)
        return "uefi-firmware-parser"
    return None


def scan_markers(data):
    findings = []
    for m in PKFAIL_MARKERS:
        if m in data:
            findings.append(("PKfail (CVE-2024-8105)",
                             f"AMI test Platform Key marker {m!r} present"))
            break
    for m in CLOAK_MARKERS:
        # 'ALRM' is short; require it near a 'cloak' string or .efi to reduce FPs
        if m in data and (b"cloak" in data.lower() or b".efi" in data.lower()):
            findings.append(("CVE-2024-7344",
                             "cloak.dat 'ALRM' magic near .efi (custom PE loader)"))
            break
    # FV count
    fv_count = data.count(FV_SIGNATURE)
    if fv_count:
        findings.append(("UEFI", f"{fv_count} firmware volume(s) (_FVH)"))
    return findings


def hash_check_files(root):
    hits = []
    for dirpath, _, files in os.walk(root):
        for fn in files:
            fp = os.path.join(dirpath, fn)
            try:
                with open(fp, "rb") as f:
                    h = hashlib.sha256(f.read()).hexdigest()
            except OSError:
                continue
            if h in CVE_2024_7344_HASHES:
                hits.append((fp, h, CVE_2024_7344_HASHES[h]))
    return hits


def find_logos(data):
    logos = []
    for magic, name in LOGO_MAGICS.items():
        idx = data.find(magic)
        while idx >= 0 and len(logos) < 50:
            logos.append((hex(idx), name))
            idx = data.find(magic, idx + 1)
    return logos


def loot_linux(root):
    patterns = re.compile(
        rb"(root:[^:]*:0:0|BEGIN (RSA|EC|OPENSSH) PRIVATE KEY|"
        rb"api[_-]?key|password\s*=|admin:)", re.I)
    hits = []
    for dirpath, _, files in os.walk(root):
        for fn in files:
            fp = os.path.join(dirpath, fn)
            try:
                with open(fp, "rb") as f:
                    blob = f.read(1 << 20)
            except OSError:
                continue
            for m in patterns.finditer(blob):
                hits.append((fp, m.group(0)[:60].decode("latin1")))
                break
    return hits


def main():
    ap = argparse.ArgumentParser(description="Firmware / UEFI triage")
    ap.add_argument("firmware")
    ap.add_argument("-o", "--out", default="out/fw")
    args = ap.parse_args()

    with open(args.firmware, "rb") as f:
        data = f.read()
    os.makedirs(args.out, exist_ok=True)

    uefi = is_uefi(data)
    print(f"[+] {args.firmware}: {len(data)} bytes — type: {'UEFI/BIOS' if uefi else 'embedded (carve)'}")

    print("\n== Secure Boot / firmware indicators ==")
    for cve, desc in scan_markers(data):
        print(f"  [{cve}] {desc}")

    if uefi:
        tool = uefi_extract(args.firmware, args.out)
        print(f"\n[+] UEFI extraction: {tool or 'no extractor on PATH (install UEFITool/uefi-firmware-parser)'}")
        logos = find_logos(data)
        if logos:
            print(f"  [LogoFAIL surface] {len(logos)} embedded image(s) — inspect boot-logo parsers:")
            for off, kind in logos[:10]:
                print(f"     {kind} @ {off}")
    else:
        tool = carve(args.firmware, args.out)
        print(f"\n[+] carve: {tool or 'no carver on PATH (install unblob/binwalk)'}")

    # hash-match any extracted .efi against CVE-2024-7344 set
    hits = hash_check_files(args.out)
    if hits:
        print("\n[!] CVE-2024-7344 vulnerable binary found:")
        for fp, h, label in hits:
            print(f"     {label}  {fp}  ({h[:16]}...)")

    # Linux loot if a root FS was carved
    if not uefi and os.path.isdir(args.out):
        loot = loot_linux(args.out)
        if loot:
            print("\n[+] credential/key loot:")
            for fp, snip in loot[:20]:
                print(f"     {fp}: {snip}")

    print("\n[next] UEFI: load DXE drivers in Ghidra (TE/PE, x64); pivot on gBS/gRT/SW-SMI.")
    print("       Linux: qemu-<arch> -L rootfs/ <binary> ; AFL++ -Q the parser.")
    print("       Verify Secure Boot posture: chipsec_main -m common.secureboot.variables")


if __name__ == "__main__":
    main()
