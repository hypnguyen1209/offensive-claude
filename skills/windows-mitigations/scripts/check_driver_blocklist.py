#!/usr/bin/env python3
"""
check_driver_blocklist.py - Pre-flight a candidate BYOVD driver: will it (a) load under HVCI/
Secure Boot and (b) evade the Microsoft Vulnerable Driver Blocklist and the LOLDrivers database?

The 2024-2026 trend (Check Point "Silver Fox" amsdk.sys) is to use a vulnerable driver that is
NOT in either list, so a load attempt does not trip a hard IOC. This tool computes the driver's
SHA256 + Authenticode page-hash candidate and checks it against:
  * the Microsoft recommended driver blocklist (WDAC policy XML or a JSON of FileRule hashes),
  * the LOLDrivers database (JSON export from loldrivers.io: /api/drivers.json),
and parses the PE signature/characteristics to flag likely HVCI/Secure-Boot load issues.

Usage:
    python check_driver_blocklist.py mydriver.sys
    python check_driver_blocklist.py mydriver.sys --loldrivers loldrivers.json
    python check_driver_blocklist.py mydriver.sys --blocklist SiPolicy.xml
    python check_driver_blocklist.py mydriver.sys --loldrivers loldrivers.json --blocklist SiPolicy.xml

Get LOLDrivers JSON:  curl -o loldrivers.json https://www.loldrivers.io/api/drivers.json
Get MS blocklist XML: https://learn.microsoft.com/.../microsoft-recommended-driver-block-rules

Dependencies: standard library only (hashlib, struct, json, xml). For authorized research only.
"""
import argparse
import hashlib
import json
import os
import re
import struct
import sys
import xml.etree.ElementTree as ET


def file_hashes(path):
    with open(path, "rb") as f:
        data = f.read()
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
    }, data


def pe_signing_posture(data):
    """Inspect PE to flag HVCI/Secure-Boot load risk heuristics."""
    out = {"is_pe": False, "has_security_dir": False, "force_integrity": False,
           "machine": None, "subsystem": None}
    if data[:2] != b"MZ":
        return out
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return out
    out["is_pe"] = True
    coff = e_lfanew + 4
    out["machine"] = {0x8664: "x64", 0x14C: "x86", 0xAA64: "arm64"}.get(
        struct.unpack_from("<H", data, coff)[0], "other")
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    pe32p = (magic == 0x20B)
    dllchar = struct.unpack_from("<H", data, opt + 0x46)[0]
    out["force_integrity"] = bool(dllchar & 0x0080)  # FORCE_INTEGRITY
    out["subsystem"] = struct.unpack_from("<H", data, opt + 0x44)[0]  # 1 = NATIVE (driver)
    # Certificate (security) directory: index 4
    ddir = opt + (0x70 if pe32p else 0x60)
    sec_rva, sec_size = struct.unpack_from("<II", data, ddir + 4 * 8)
    out["has_security_dir"] = (sec_rva != 0 and sec_size != 0)
    return out


def load_loldrivers(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        db = json.load(f)
    hashes = set()
    if isinstance(db, list):
        for entry in db:
            for s in entry.get("KnownVulnerableSamples", []) or []:
                for k in ("SHA256", "SHA1", "MD5"):
                    v = s.get(k)
                    if v:
                        hashes.add(v.lower())
    return hashes


def load_ms_blocklist(path):
    """Parse a WDAC SiPolicy XML (or any XML containing FileRules with Hash attrs).

    Hardening: a WDAC policy is a trusted local artifact, but to be safe against XXE /
    billion-laughs we parse with a parser that does not resolve external entities. Python's
    stdlib expat does not fetch external DTDs/entities by default; we additionally trap on any
    entity declaration. (Use defusedxml.ElementTree if available in your environment for
    defence-in-depth against fully untrusted XML.)
    """
    hashes = set()
    try:
        parser = ET.XMLParser()
        # Reject internal entity definitions outright (billion-laughs guard).
        if hasattr(parser, "entity"):
            class _NoEntities(dict):
                def __setitem__(self, k, v):
                    raise ValueError("entity declarations are not allowed")
            parser.entity = _NoEntities()
        tree = ET.parse(path, parser=parser)
    except (ET.ParseError, ValueError):
        # fall back: regex-scrape hex hashes from the text
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for h in re.findall(r"\b[0-9A-Fa-f]{40,64}\b", f.read()):
                hashes.add(h.lower())
        return hashes
    for el in tree.iter():
        for attr in ("Hash", "hash"):
            v = el.get(attr)
            if v:
                hashes.add(v.replace(" ", "").lower())
    return hashes


def main():
    ap = argparse.ArgumentParser(description="Pre-flight a BYOVD driver against blocklist/LOLDrivers/HVCI.")
    ap.add_argument("driver", help="candidate .sys file")
    ap.add_argument("--loldrivers", help="loldrivers.io drivers.json")
    ap.add_argument("--blocklist", help="MS recommended driver block rules (WDAC SiPolicy XML)")
    args = ap.parse_args()

    if not os.path.exists(args.driver):
        print(f"[!] {args.driver} not found", file=sys.stderr)
        sys.exit(2)

    h, data = file_hashes(args.driver)
    pe = pe_signing_posture(data)

    print(f"[*] Driver : {args.driver}")
    print(f"    SHA256 : {h['sha256']}")
    print(f"    SHA1   : {h['sha1']}")
    print(f"    MD5    : {h['md5']}")
    print(f"    PE     : machine={pe['machine']} signed_blob={pe['has_security_dir']} "
          f"force_integrity={pe['force_integrity']} subsystem={pe['subsystem']}")

    verdict_load = True
    verdict_stealth = True

    # --- LOLDrivers ---
    if args.loldrivers:
        lol = load_loldrivers(args.loldrivers)
        hit = {k: h[k] for k in ("sha256", "sha1", "md5") if h[k].lower() in lol}
        if hit:
            print(f"[X] LISTED in LOLDrivers ({', '.join(hit.keys())}) -> EDRs hunt this hash. NOT stealthy.")
            verdict_stealth = False
        else:
            print("[+] Not found in LOLDrivers database.")
    else:
        print("[i] LOLDrivers check skipped (pass --loldrivers drivers.json).")

    # --- MS blocklist ---
    if args.blocklist:
        bl = load_ms_blocklist(args.blocklist)
        hit = {k: h[k] for k in ("sha256", "sha1") if h[k].lower() in bl}
        if hit:
            print(f"[X] BLOCKED by Microsoft Vulnerable Driver Blocklist ({', '.join(hit.keys())}) "
                  "-> will NOT load where blocklist enforced.")
            verdict_load = False
        else:
            print("[+] Not matched in supplied Microsoft blocklist.")
            print("    (Note: blocklist also has filename/version/cert rules this hash check "
                  "does not cover - verify by name/signer too.)")
    else:
        print("[i] MS blocklist check skipped (pass --blocklist SiPolicy.xml).")

    # --- HVCI / Secure Boot heuristics ---
    print("\n[*] HVCI / Secure Boot load heuristics:")
    if not pe["has_security_dir"]:
        print("    [X] No embedded signature blob -> will NOT load under Secure Boot/HVCI "
              "without test-signing. (Catalog-signed drivers may still load.)")
        verdict_load = False
    else:
        print("    [+] Has an embedded Authenticode signature blob.")
    if pe["machine"] != "x64":
        print(f"    [!] Architecture {pe['machine']} - confirm it matches the target OS.")
    print("    [i] HVCI/Secure Boot can still reject a signed-but-incompatible driver (WHQL/EV "
          "requirements, page-hash mismatch). ALWAYS test-load on a matching Secure-Boot+HVCI host.")

    print("\n=== VERDICT ===")
    print(f"  Likely to LOAD under HVCI/Secure Boot : {'maybe (test it)' if verdict_load else 'NO'}")
    print(f"  Stealthy vs blocklist/LOLDrivers      : {'yes' if verdict_stealth and verdict_load else 'NO'}")
    if verdict_load and verdict_stealth:
        print("  -> Candidate looks unblocked + unlisted. Still: minimize dwell, unload + delete "
              "the .sys and the service key after the data-only kernel edit.")
    sys.exit(0 if (verdict_load and verdict_stealth) else 1)


if __name__ == "__main__":
    main()
