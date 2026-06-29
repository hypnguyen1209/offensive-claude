#!/usr/bin/env python3
"""
patchdiff_fetch.py - acquire pre- and post-patch copies of a Windows binary from
Winbindex (m417z) for BinDiff / Diaphora / ghidriff, without maintaining a VM farm.

Winbindex hosts a per-file JSON index of every version of a given Windows binary,
keyed by KB / version / hash, plus direct download links to the binaries on the
Microsoft Symbol Server / Delta-patched store.

Given a target PE and the KB that shipped the fix, this fetches the version that
appeared in that KB ("after") and the immediately-preceding version ("before").

Usage:
    python3 patchdiff_fetch.py --pe afd.sys --kb-after KB5050000 -o out/diff/
    python3 patchdiff_fetch.py --pe ntoskrnl.exe --list            # list known versions
    python3 patchdiff_fetch.py --pe clfs.sys --version-after 10.0.26100.3000 -o out/diff/

Dependencies:
    pip install requests
Notes:
    Winbindex data URL pattern (subject to change — verify against winbindex.m417z.com):
      https://winbindex.m417z.com/data/by_filename_compressed/<file>.json.gz
    The script is defensive about schema drift and prints next-step diff commands.
"""
import argparse
import gzip
import io
import json
import os
import sys

try:
    import requests
except ImportError:
    print("error: pip install requests", file=sys.stderr)
    sys.exit(1)

WINBINDEX = "https://winbindex.m417z.com/data/by_filename_compressed/{file}.json.gz"


def fetch_index(pe_name):
    url = WINBINDEX.format(file=pe_name.lower())
    r = requests.get(url, timeout=60)
    r.raise_for_status()
    raw = gzip.decompress(r.content)
    return json.loads(raw)


def versions_from_index(index):
    """Return list of dicts: {hash, version, kbs:[...], download_url}."""
    out = []
    for file_hash, entry in index.items():
        fi = entry.get("fileInfo", {})
        version = fi.get("version") or fi.get("productVersion") or "?"
        kbs = []
        for upd in entry.get("windowsVersions", {}).values():
            for rel in upd.values():
                kb = rel.get("updateKb") or rel.get("kb")
                if kb:
                    kbs.append("KB" + str(kb) if not str(kb).startswith("KB") else str(kb))
        # download link: VirusTotal-style or MS symbol server (timestamp+size)
        dl = None
        ts = fi.get("timestamp")
        size = fi.get("virtualSize") or fi.get("size")
        if ts is not None and size is not None:
            dl = (f"https://msdl.microsoft.com/download/symbols/"
                  f"{pe_global}/{int(ts):08X}{int(size):x}/{pe_global}")
        out.append({"hash": file_hash, "version": version,
                    "kbs": sorted(set(kbs)), "download_url": dl})
    out.sort(key=lambda x: _vkey(x["version"]))
    return out


def _vkey(v):
    try:
        return tuple(int(p) for p in v.split("."))
    except Exception:
        return (0,)


def download(url, dest):
    if not url:
        return False
    r = requests.get(url, timeout=120)
    if r.status_code != 200:
        return False
    with open(dest, "wb") as f:
        f.write(r.content)
    return True


def main():
    global pe_global
    ap = argparse.ArgumentParser(description="Fetch pre/post-patch Windows binaries via Winbindex")
    ap.add_argument("--pe", required=True, help="binary name, e.g. afd.sys / ntoskrnl.exe")
    ap.add_argument("--kb-after", help="KB that shipped the fix (the 'after' version)")
    ap.add_argument("--version-after", help="explicit 'after' version string")
    ap.add_argument("--list", action="store_true", help="list known versions and exit")
    ap.add_argument("-o", "--out", default="out/diff")
    args = ap.parse_args()

    pe_global = args.pe.lower()
    index = fetch_index(args.pe)
    vers = versions_from_index(index)
    print(f"[+] {args.pe}: {len(vers)} indexed version(s)")

    if args.list:
        for v in vers[-40:]:
            print(f"   {v['version']:<22} {','.join(v['kbs']) or '-'}")
        return

    # locate the 'after' version
    after_idx = None
    for i, v in enumerate(vers):
        if args.version_after and v["version"] == args.version_after:
            after_idx = i
            break
        if args.kb_after and any(args.kb_after.upper() == k.upper() for k in v["kbs"]):
            after_idx = i
            break
    if after_idx is None:
        print("[-] could not match --kb-after/--version-after; use --list to inspect.",
              file=sys.stderr)
        sys.exit(2)

    after = vers[after_idx]
    before = vers[after_idx - 1] if after_idx > 0 else None
    os.makedirs(args.out, exist_ok=True)

    for label, v in (("after", after), ("before", before)):
        if not v:
            print(f"[-] no '{label}' version available")
            continue
        dest = os.path.join(args.out, f"{args.pe}.{label}")
        ok = download(v["download_url"], dest)
        print(f"[{'+' if ok else '-'}] {label}: v{v['version']} "
              f"{'-> ' + dest if ok else '(no direct URL; fetch from Update Catalog/VT manually)'}")

    print("\n[next] diff the two files:")
    print(f"   ghidriff {args.out}/{args.pe}.before {args.out}/{args.pe}.after -o {args.out}/report")
    print(f"   # or BinDiff: BinExport each in IDA/Ghidra, then bindiff --primary before.BinExport "
          f"--secondary after.BinExport --output_dir {args.out}")
    print("   triage smallest changed functions first; pin the exact versions in your finding.")


if __name__ == "__main__":
    main()
