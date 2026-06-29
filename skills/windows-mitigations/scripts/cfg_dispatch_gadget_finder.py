#!/usr/bin/env python3
"""
cfg_dispatch_gadget_finder.py - Parse a PE's Guard CF Function Table (CFG-valid indirect-call
targets) and flag candidate "dispatch gadgets" usable to defeat CFG/XFG via a vtable/function-
pointer overwrite. Under CFG only the call TARGET is validated, so an attacker swaps a function
pointer for any function whose RVA is in the Guard CF table.

What it does:
  * Locates IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, reads GuardCFFunctionTable + count.
  * Decodes each entry (RVA [+ optional 1-byte flags when GuardFlags indicates a stride]).
  * Reports table size, stride, XFG presence, and (with a symbol map) flags exports whose names
    match known control-redirect primitives (longjmp, _chkstk, dispatch thunks, etc.).

Usage:
    python cfg_dispatch_gadget_finder.py target.dll
    python cfg_dispatch_gadget_finder.py target.dll --xfg            # note XFG type-hash stride
    python cfg_dispatch_gadget_finder.py target.dll --map syms.csv   # csv: rva,name

Dependencies: standard library only. For authorized engagement / exploit research use only.
"""
import argparse
import struct
import sys

IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10

# GuardFlags bits relevant to the function-table entry stride
IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT = 0x00000400
# bits 28..31 hold (stride extra bytes); mask + shift per winnt.h
IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK = 0xF0000000
IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT = 28
IMAGE_GUARD_XFG_ENABLED = 0x00800000

# Export names that commonly serve as CFG-valid control-redirect / dispatch primitives.
DISPATCH_HINTS = (
    "longjmp", "setjmp", "_chkstk", "guard_dispatch", "guard_check",
    "RtlRestoreContext", "RtlCaptureContext", "NtContinue", "KiUserExceptionDispatcher",
    "coroutine", "Resume", "vftable", "dtor", "Invoke",
)


def read_pe(path):
    with open(path, "rb") as f:
        return f.read()


def rva_to_off(data, sections, rva):
    for vaddr, vsize, praw in sections:
        if vaddr <= rva < vaddr + max(vsize, 1):
            return praw + (rva - vaddr)
    return None


def parse(data):
    if data[:2] != b"MZ":
        raise ValueError("not a PE (no MZ)")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("not a PE (no PE signature)")
    coff = e_lfanew + 4
    num_sections = struct.unpack_from("<H", data, coff + 2)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    pe32p = (magic == 0x20B)
    image_base = struct.unpack_from("<Q" if pe32p else "<I", data, opt + (0x18 if pe32p else 0x1C))[0]
    # number of RVA/sizes + data directory start
    ddir = opt + (0x70 if pe32p else 0x60)
    # optional header size to find section table
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    sec_tab = opt + opt_size

    sections = []
    for i in range(num_sections):
        b = sec_tab + i * 40
        vsize = struct.unpack_from("<I", data, b + 8)[0]
        vaddr = struct.unpack_from("<I", data, b + 12)[0]
        praw = struct.unpack_from("<I", data, b + 20)[0]
        sections.append((vaddr, vsize, praw))

    lc_rva, lc_size = struct.unpack_from("<II", data, ddir + IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG * 8)
    return pe32p, image_base, sections, lc_rva, lc_size


def main():
    ap = argparse.ArgumentParser(description="Find CFG-valid dispatch-gadget candidates in a PE.")
    ap.add_argument("pe")
    ap.add_argument("--xfg", action="store_true", help="report XFG type-hash details")
    ap.add_argument("--map", help="CSV of 'rva,name' to annotate gadget candidates")
    args = ap.parse_args()

    data = read_pe(args.pe)
    pe32p, base, sections, lc_rva, lc_size = parse(data)
    if not lc_rva:
        print("[-] No load-config directory: image has no CFG metadata.")
        sys.exit(0)

    lc_off = rva_to_off(data, sections, lc_rva)
    ptr = "<Q" if pe32p else "<I"
    psz = 8 if pe32p else 4

    # Offsets within IMAGE_LOAD_CONFIG_DIRECTORY (x64 layout):
    # GuardCFCheckFunctionPointer    @ 0x70
    # GuardCFDispatchFunctionPointer @ 0x78
    # GuardCFFunctionTable           @ 0x80
    # GuardCFFunctionCount           @ 0x88
    # GuardFlags                     @ 0x90
    if pe32p:
        gcf_table = struct.unpack_from(ptr, data, lc_off + 0x80)[0]
        gcf_count = struct.unpack_from(ptr, data, lc_off + 0x88)[0]
        gflags = struct.unpack_from("<I", data, lc_off + 0x90)[0]
    else:
        gcf_table = struct.unpack_from(ptr, data, lc_off + 0x80)[0]
        gcf_count = struct.unpack_from(ptr, data, lc_off + 0x88)[0]
        gflags = struct.unpack_from("<I", data, lc_off + 0x90)[0]

    has_table = bool(gflags & IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT)
    extra = (gflags & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK) >> IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT
    stride = 4 + extra  # 4-byte RVA + extra metadata bytes per entry
    xfg = bool(gflags & IMAGE_GUARD_XFG_ENABLED)

    print(f"[*] {args.pe}")
    print(f"    GuardFlags        : 0x{gflags:08x}")
    print(f"    CF table present  : {has_table}")
    print(f"    XFG enabled       : {xfg}")
    print(f"    Entry stride      : {stride} bytes (4-byte RVA + {extra} metadata)")
    print(f"    Function count    : {gcf_count}")
    if args.xfg and xfg:
        print("    [XFG] each valid target also has a per-prototype type hash; a dispatch")
        print("          gadget must be TYPE-HASH COMPATIBLE with the overwritten call site.")

    if not has_table or gcf_count == 0 or gcf_table == 0:
        print("[-] No usable Guard CF function table; CFG may rely on imported check only.")
        return

    tbl_rva = gcf_table - base
    tbl_off = rva_to_off(data, sections, tbl_rva)
    if tbl_off is None:
        print("[-] Could not map function-table RVA to file offset.")
        return

    # Load optional symbol map (rva -> name)
    names = {}
    if args.map:
        with open(args.map) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                rva_s, _, nm = line.partition(",")
                try:
                    names[int(rva_s, 0)] = nm.strip()
                except ValueError:
                    pass

    print(f"\n[*] CFG-valid call targets (first 4000 shown):")
    candidates = []
    for i in range(min(gcf_count, 4000)):
        ent = tbl_off + i * stride
        if ent + 4 > len(data):
            break
        target_rva = struct.unpack_from("<I", data, ent)[0]
        flag = data[ent + 4] if stride > 4 and ent + 4 < len(data) else None
        nm = names.get(target_rva, "")
        is_cand = any(h.lower() in nm.lower() for h in DISPATCH_HINTS) if nm else False
        if is_cand:
            candidates.append((target_rva, nm))
        if i < 50 or is_cand:
            tag = "  <-- DISPATCH CANDIDATE" if is_cand else ""
            extra_s = f" flags=0x{flag:02x}" if flag is not None else ""
            print(f"    RVA=0x{target_rva:08x}{extra_s} {nm}{tag}")

    print()
    if candidates:
        print(f"[+] {len(candidates)} dispatch-gadget candidate(s) (CFG-valid, name-matched):")
        for rva, nm in candidates:
            print(f"    0x{rva:08x}  {nm}")
        print("    -> overwrite a function pointer / vtable slot with one of these to redirect")
        print("       control while passing CFG. Under XFG, match the call-site type hash.")
    else:
        print("[*] No name-matched candidates (supply --map with exported symbol RVAs to annotate).")
        print("    Any RVA in the table is still a CFG-valid target; pick one whose prologue")
        print("    yields useful control flow (longjmp/dispatch/destructor thunks).")


if __name__ == "__main__":
    main()
