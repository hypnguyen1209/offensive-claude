#!/usr/bin/env python3
r"""
ioctl_fuzzer.py - Driver IOCTL attack-surface mapper + dumb fuzzer for the kernel/user
boundary. Discovers a driver's device object, brute-forces valid IOCTL codes, and fuzzes
input buffers to surface unauthenticated R/W primitives (the BYOVD precursor) or DoS bugs.

What it does:
  1. Open \\.\<device> with GENERIC_READ|GENERIC_WRITE (0 access fallback).
  2. Sweep the 32-bit CTL_CODE space intelligently: iterate FUNCTION (0x800-0xFFF) x
     METHOD (0..3) for the common device types, recording which codes do NOT return
     ERROR_INVALID_FUNCTION (0x1F) -> the driver handles them.
  3. For each valid code, fuzz the input buffer (sizes + mutated content) and flag:
       - codes that accept attacker-controlled pointers (METHOD_NEITHER, type 3) -> classic
         arbitrary-R/W primitive surface
       - crashes / hangs (potential DoS or memory corruption)

USAGE:
  python ioctl_fuzzer.py --device RTCore64 --map
  python ioctl_fuzzer.py --device LnvMSRIO --fuzz --iterations 2000

DEPENDS: Windows, Python 3.8+, stdlib ctypes only. Run with the same integrity as the
target's access ACL allows. AUTHORIZED testing of your own/permitted driver ONLY.

OPSEC: opening a device + DeviceIoControl storms are visible to ETW Microsoft-Windows-Kernel-
File / driver-specific providers; a crash produces a bugcheck/minidump (EID 1001).
See references/kernel-user-boundary.md.
"""
import argparse
import ctypes
import os
import random
import sys
from ctypes import wintypes

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
ERROR_INVALID_FUNCTION = 1
ERROR_NOT_SUPPORTED = 50

# CTL_CODE(DeviceType, Function, Method, Access)
def ctl_code(devtype, func, method, access):
    return (devtype << 16) | (access << 14) | (func << 2) | method

METHOD_BUFFERED = 0
METHOD_IN_DIRECT = 1
METHOD_OUT_DIRECT = 2
METHOD_NEITHER = 3
FILE_ANY_ACCESS = 0
FILE_READ_DATA = 1
FILE_WRITE_DATA = 2


def open_device(name):
    for path in (rf"\\.\{name}", rf"\\.\Global\{name}"):
        for access in (GENERIC_READ | GENERIC_WRITE, 0):
            h = kernel32.CreateFileW(path, access, 0, None, OPEN_EXISTING, 0, None)
            if h != INVALID_HANDLE_VALUE:
                return h, path
    return None, None


def ioctl(h, code, in_buf):
    out = ctypes.create_string_buffer(0x1000)
    ret = wintypes.DWORD(0)
    in_p = ctypes.create_string_buffer(in_buf) if in_buf else None
    ok = kernel32.DeviceIoControl(
        h, code, in_p, len(in_buf) if in_buf else 0,
        out, ctypes.sizeof(out), ctypes.byref(ret), None,
    )
    return ok, ctypes.get_last_error(), ret.value


# Common device types to sweep (custom drivers usually use 0x22 FILE_DEVICE_UNKNOWN)
DEV_TYPES = [0x22, 0x00000009, 0x0000002B]  # UNKNOWN, NETWORK, ACPI-ish


def map_surface(h):
    valid = []
    for devtype in DEV_TYPES:
        for func in range(0x800, 0x1000):
            for method in (METHOD_BUFFERED, METHOD_NEITHER):
                for access in (FILE_ANY_ACCESS, FILE_READ_DATA | FILE_WRITE_DATA):
                    code = ctl_code(devtype, func, method, access)
                    ok, err, _ = ioctl(h, code, b"\x00" * 8)
                    if not ok and err in (ERROR_INVALID_FUNCTION, ERROR_NOT_SUPPORTED):
                        continue
                    flag = "ARB-RW-RISK" if method == METHOD_NEITHER else "handled"
                    valid.append((code, devtype, func, method, access, err, flag))
    return valid


def fuzz_code(h, code, iterations):
    findings = []
    for _ in range(iterations):
        size = random.choice([4, 8, 16, 24, 32, 64, 0x1000])
        # bias toward pointer-looking values (kernel R/W primitives dereference these)
        buf = b"".join(
            random.choice([
                random.randbytes(1),
                (0xFFFFF80000000000 + random.randint(0, 0xFFFFFF)).to_bytes(8, "little"),
            ])
            for _ in range(size)
        )[:size]
        try:
            ok, err, ret = ioctl(h, code, buf)
        except OSError as e:
            findings.append((code, "EXCEPTION", str(e), buf.hex()[:32]))
            continue
        if ok and ret > 0:
            findings.append((code, "OUTPUT", f"ret={ret}", buf.hex()[:32]))
    return findings


def main():
    ap = argparse.ArgumentParser(description="Driver IOCTL surface mapper / fuzzer")
    ap.add_argument("--device", required=True, help="device name, e.g. RTCore64")
    ap.add_argument("--map", action="store_true", help="enumerate valid IOCTL codes")
    ap.add_argument("--fuzz", action="store_true", help="fuzz discovered codes")
    ap.add_argument("--iterations", type=int, default=1000)
    args = ap.parse_args()

    h, path = open_device(args.device)
    if not h:
        sys.exit(f"[-] could not open device '{args.device}' (err {ctypes.get_last_error()})")
    print(f"[+] opened {path}")

    valid = []
    if args.map or args.fuzz:
        print("[*] mapping IOCTL surface (this sweeps the function space)...")
        valid = map_surface(h)
        print(f"[+] {len(valid)} handled IOCTL codes")
        for code, dt, fn, m, ac, err, flag in valid:
            print(f"    0x{code:08X}  dev=0x{dt:X} func=0x{fn:X} method={m} acc={ac} -> {flag}")

    if args.fuzz:
        risky = [v[0] for v in valid if v[6] == "ARB-RW-RISK"] or [v[0] for v in valid]
        print(f"[*] fuzzing {len(risky)} codes x {args.iterations} iterations...")
        for code in risky:
            for f in fuzz_code(h, code, args.iterations):
                print(f"    [!] 0x{f[0]:08X} {f[1]} {f[2]} input={f[3]}")

    kernel32.CloseHandle(h)


if __name__ == "__main__":
    if not sys.platform.startswith("win"):
        sys.exit("Windows only.")
    if not hasattr(random, "randbytes"):
        random.randbytes = lambda n: bytes(random.getrandbits(8) for _ in range(n))
    main()
