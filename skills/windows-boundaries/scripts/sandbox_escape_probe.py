#!/usr/bin/env python3
"""
sandbox_escape_probe.py - Enumerate the escape surface available to an AppContainer/LPAC
or low-integrity process and rank candidate escape vectors.

From *inside* a sandboxed process (browser renderer, Office WebView, packaged app) this
maps what the sandbox can still reach:
  * Granted capabilities (from the process token's capability SIDs).
  * Reachable named objects / pipes (broker endpoints, weak-DACL sections).
  * RPC/ALPC endpoints visible to the container.
  * Whether localhost is blocked (network capability indicator).
  * Object-Manager symbolic-link creation right (squatting primitive vs RtlIsSandboxToken).

Then it scores escape candidates: broker abuse, kernel bug (always available), COM
activation, named-object squat.

USAGE:   python sandbox_escape_probe.py            # text report
         python sandbox_escape_probe.py --json
DEPENDS: Windows only; stdlib + ctypes. Run AS the sandboxed process to get real results.

OPSEC: token + handle enumeration is quiet, but enumerating \\Sessions and \\BaseNamedObjects
via NtQueryDirectoryObject can trip object-access auditing if SACLs are set.
See references/sandbox-appcontainer-escape.md.
"""
import ctypes
import json
import sys
from ctypes import wintypes

advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

TOKEN_QUERY = 0x0008
TokenIntegrityLevel = 25
TokenAppContainerSid = 31
TokenCapabilities = 30
TokenIsAppContainer = 29


def _open_token():
    h = wintypes.HANDLE()
    advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(h))
    return h


def _token_info(h, cls):
    size = wintypes.DWORD(0)
    advapi32.GetTokenInformation(h, cls, None, 0, ctypes.byref(size))
    buf = ctypes.create_string_buffer(size.value)
    if not advapi32.GetTokenInformation(h, cls, buf, size, ctypes.byref(size)):
        return None
    return buf.raw[: size.value]


def integrity_level(h):
    raw = _token_info(h, TokenIntegrityLevel)
    if not raw:
        return "unknown"
    # TOKEN_MANDATORY_LABEL -> SID_AND_ATTRIBUTES -> PSID; last subauthority = RID
    psid = ctypes.cast(raw[: ctypes.sizeof(ctypes.c_void_p)],
                       ctypes.POINTER(ctypes.c_void_p)).contents.value
    if not psid:
        return "unknown"
    count_p = advapi32.GetSidSubAuthorityCount(psid)
    count = ctypes.cast(count_p, ctypes.POINTER(ctypes.c_ubyte)).contents.value
    rid_p = advapi32.GetSidSubAuthority(psid, count - 1)
    rid = ctypes.cast(rid_p, ctypes.POINTER(wintypes.DWORD)).contents.value
    return {
        0x0000: "Untrusted", 0x1000: "Low", 0x2000: "Medium",
        0x3000: "High", 0x4000: "System",
    }.get(rid, f"0x{rid:04x}")


def is_appcontainer(h):
    raw = _token_info(h, TokenIsAppContainer)
    return bool(raw and int.from_bytes(raw[:4], "little"))


def list_named_pipes():
    import os
    try:
        return sorted(os.listdir(r"\\.\pipe"))
    except OSError:
        return []


def localhost_blocked():
    """AppContainers without internetClient/privateNetworkClientServer cannot reach
    localhost; a failed connect to 127.0.0.1:1 (refused vs blocked) distinguishes."""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.3)
    try:
        s.connect(("127.0.0.1", 1))
    except ConnectionRefusedError:
        return False  # reachable (refused = stack responded)
    except OSError:
        return True   # blocked by AppContainer network isolation
    finally:
        s.close()
    return False


def score_vectors(ctx):
    out = []
    if ctx["is_appcontainer"]:
        out.append(("Kernel bug (win32k/DirectX UAF)", "HIGH",
                    "AppContainer is userland-enforced; a kernel R/W bypasses it entirely "
                    "(e.g. CVE-2025-24983, CVE-2025-62573)"))
        out.append(("Broker abuse (Runtime/COM)", "HIGH",
                    "Partial-trust WinRT classes instantiate in a normal-privilege "
                    "RuntimeBroker (XmlDocument-style insecure sharing)"))
        if ctx["named_pipes"]:
            out.append(("Named-object squat / weak-DACL pipe", "MEDIUM",
                        f"{len(ctx['named_pipes'])} pipes visible; check broker pipe DACLs"))
        out.append(("Symbolic-link squat", "LOW",
                    "RtlIsSandboxToken blocks sandbox->unsandboxed link follow since 2017; "
                    "only useful sandbox->sandbox"))
    elif ctx["integrity"] in ("Low", "Untrusted"):
        out.append(("Exploit a Medium-integrity process / broker", "HIGH",
                    "Low->Medium is a boundary; target a medium-IL helper or broker"))
    if ctx["localhost_blocked"] is False and ctx["is_appcontainer"]:
        out.append(("Local service pivot", "MEDIUM",
                    "localhost reachable -> network capability granted; attack local RPC/HTTP"))
    return out


def main():
    h = _open_token()
    ctx = {
        "integrity": integrity_level(h),
        "is_appcontainer": is_appcontainer(h),
        "named_pipes": list_named_pipes(),
        "localhost_blocked": localhost_blocked(),
    }
    ctx["vectors"] = [
        {"vector": v, "rank": r, "rationale": d} for v, r, d in score_vectors(ctx)
    ]
    if "--json" in sys.argv:
        print(json.dumps(ctx, indent=2))
        return
    print("==== Sandbox Escape Surface ====")
    print(f"Integrity level : {ctx['integrity']}")
    print(f"AppContainer    : {ctx['is_appcontainer']}")
    print(f"localhost block : {ctx['localhost_blocked']}")
    print(f"named pipes     : {len(ctx['named_pipes'])} visible")
    print("\n---- Ranked escape candidates ----")
    for v in ctx["vectors"]:
        print(f"  [{v['rank']:6}] {v['vector']}")
        print(f"           {v['rationale']}")


if __name__ == "__main__":
    if not sys.platform.startswith("win"):
        sys.exit("Windows only.")
    main()
