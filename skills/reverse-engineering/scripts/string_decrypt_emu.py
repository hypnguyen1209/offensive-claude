#!/usr/bin/env python3
"""
string_decrypt_emu.py - recover obfuscated strings by EMULATING the in-binary
decrypt routine (instead of reimplementing the algorithm).

Maps the binary's code, sets up a stack and a scratch data page, points the first
integer argument at an encrypted blob, runs the target function under Unicorn until
it returns, then reads back the (now plaintext) buffer.

Supports x86-64 and x86 (--arch x86). The first arg is passed in RDI (SysV) by
default, or on the stack for x86 cdecl. Use --auto-xref to dump the call sites that
should be emulated (requires capstone) so you can batch over every reference.

Usage:
    # single blob (point RDI at a scratch page we fill with enc_blob.bin):
    python3 string_decrypt_emu.py ./sample --func 0x401500 --data-file enc_blob.bin -o out/one.txt

    # list candidate call sites to the decryptor for batch emulation:
    python3 string_decrypt_emu.py ./sample --func 0x401500 --auto-xref

Dependencies:
    pip install unicorn capstone lief
"""
import argparse
import sys

try:
    from unicorn import (Uc, UC_ARCH_X86, UC_MODE_64, UC_MODE_32, UC_HOOK_CODE,
                         UcError)
    from unicorn.x86_const import (UC_X86_REG_RSP, UC_X86_REG_RDI, UC_X86_REG_RIP,
                                   UC_X86_REG_ESP)
except ImportError:
    print("error: pip install unicorn", file=sys.stderr)
    sys.exit(1)
try:
    import lief
except ImportError:
    lief = None
try:
    import capstone
except ImportError:
    capstone = None

CODE_BASE = 0x00400000
CODE_SIZE = 0x00200000
STACK_BASE = 0x00B00000
STACK_SIZE = 0x00100000
DATA_BASE = 0x00C00000
DATA_SIZE = 0x00010000


def load_image(path):
    """Return (raw_bytes, image_base) - flat-map the file at CODE_BASE for emulation."""
    with open(path, "rb") as f:
        data = f.read()
    base = CODE_BASE
    if lief:
        b = lief.parse(path)
        try:
            base = b.imagebase or CODE_BASE
        except Exception:
            base = CODE_BASE
    return data, base


def auto_xref(path, func_addr, arch64):
    if not (lief and capstone):
        print("auto-xref needs lief + capstone", file=sys.stderr)
        return
    b = lief.parse(path)
    sec = b.get_section(".text")
    code = bytes(sec.content)
    va = sec.virtual_address + (b.imagebase or 0)
    md = capstone.Cs(capstone.CS_ARCH_X86,
                     capstone.CS_MODE_64 if arch64 else capstone.CS_MODE_32)
    hits = []
    for ins in md.disasm(code, va):
        if ins.mnemonic == "call":
            op = ins.op_str
            try:
                tgt = int(op, 16) if op.startswith("0x") else None
            except ValueError:
                tgt = None
            if tgt == func_addr:
                hits.append(ins.address)
    print(f"[+] {len(hits)} call site(s) to {hex(func_addr)}:")
    for h in hits:
        print("   ", hex(h))
    print("    -> emulate each: set the arg to the encrypted ptr it pushes, re-run with --func")


def emulate(path, func_addr, data_blob, arg_reg_value, arch64, max_run=0x100000):
    raw, base = load_image(path)
    mu = Uc(UC_ARCH_X86, UC_MODE_64 if arch64 else UC_MODE_32)
    # map code (flat); pad to size
    map_base = base & ~0xFFF
    mu.mem_map(map_base, CODE_SIZE)
    mu.mem_write(map_base, raw[:CODE_SIZE] if len(raw) > CODE_SIZE else raw)
    # stack
    mu.mem_map(STACK_BASE, STACK_SIZE)
    sp = STACK_BASE + STACK_SIZE - 0x1000
    # data scratch page
    mu.mem_map(DATA_BASE, DATA_SIZE)
    if data_blob:
        mu.mem_write(DATA_BASE, data_blob)

    if arch64:
        mu.reg_write(UC_X86_REG_RSP, sp)
        mu.reg_write(UC_X86_REG_RDI, arg_reg_value if arg_reg_value else DATA_BASE)
        # fake return address so emu_start stops cleanly when the function returns
        ret_marker = STACK_BASE + 0x10
        mu.mem_write(sp, ret_marker.to_bytes(8, "little"))
    else:
        mu.reg_write(UC_X86_REG_ESP, sp)
        # cdecl: push arg then return marker
        ret_marker = STACK_BASE + 0x10
        mu.mem_write(sp, ret_marker.to_bytes(4, "little"))
        mu.mem_write(sp + 4, (arg_reg_value or DATA_BASE).to_bytes(4, "little"))

    stopped = {"hit": False}

    def stop_hook(uc, address, size, user):
        if address == ret_marker:
            uc.emu_stop()
            stopped["hit"] = True

    mu.hook_add(UC_HOOK_CODE, stop_hook)
    try:
        mu.emu_start(func_addr, func_addr + max_run, count=200000)
    except UcError:
        pass  # we stop via the ret marker; emulation faults at the marker are expected
    # read back the scratch page
    out = mu.mem_read(DATA_BASE, min(len(data_blob) + 64 if data_blob else 256, DATA_SIZE))
    return bytes(out)


def main():
    ap = argparse.ArgumentParser(description="Emulate a string-decrypt routine with Unicorn")
    ap.add_argument("binary")
    ap.add_argument("--func", required=True, help="decrypt function VA, e.g. 0x401500")
    ap.add_argument("--arch", choices=["x64", "x86"], default="x64")
    ap.add_argument("--data-file", help="encrypted blob to place at scratch + arg ptr")
    ap.add_argument("--arg-rdi", help="override first-arg pointer (VA)")
    ap.add_argument("--auto-xref", action="store_true",
                    help="list call sites to --func instead of emulating")
    ap.add_argument("-o", "--out")
    args = ap.parse_args()

    func_addr = int(args.func, 16)
    arch64 = args.arch == "x64"

    if args.auto_xref:
        auto_xref(args.binary, func_addr, arch64)
        return

    blob = b""
    if args.data_file:
        with open(args.data_file, "rb") as f:
            blob = f.read()
    arg_val = int(args.arg_rdi, 16) if args.arg_rdi else 0

    result = emulate(args.binary, func_addr, blob, arg_val, arch64)
    # print printable interpretation
    printable = bytes(c if 0x20 <= c < 0x7f else ord(".") for c in result)
    text = printable.split(b"\x00")[0].decode("ascii", "ignore")
    print(f"[+] decrypted (first NUL-terminated run): {text!r}")
    print(f"[+] raw hex: {result[:64].hex()}")
    if args.out:
        with open(args.out, "wb") as f:
            f.write(result)
        print(f"[+] wrote {args.out}")


if __name__ == "__main__":
    main()
