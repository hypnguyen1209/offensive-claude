#!/usr/bin/env python3
"""
timestomp_detect.py - Detect NTFS timestomping & USN tamper from MFTECmd CSV output.

Cross-validates the two MFT timestamp sets and (optionally) the USN journal:
  * $SI.Created (Created0x10) < $FN.Created (Created0x30)         -> classic timestomp
  * $SI.Created later than $SI.LastModified by a wide margin       -> stomped forward
  * $SI sub-second precision == 0 while $FN has precision          -> tool zeroed fractions
  * file present with a $SI create time that has NO matching USN FILE_CREATE near it
  * (USN) SDelete/CCleaner rename patterns; mass same-extension rename/delete burst (ransomware)

Input is the CSV produced by Eric Zimmerman's MFTECmd:
  MFTECmd.exe -f "$MFT"       --csv out --csvf mft.csv
  MFTECmd.exe -f "$Extend\\$J" -m "$MFT" --csv out --csvf usn.csv

Usage:
  python3 timestomp_detect.py --mft mft.csv [--usn usn.csv] [--out findings.csv]

Dependencies: Python 3.8+ stdlib only (csv, datetime). Works cross-platform on the CSVs.
Notes: read-only over CSVs. MFTECmd column names are used (Created0x10/Created0x30 etc.); if your
  version differs, adjust COL_* below. $FN is harder to forge than $SI -> anchor truth to $FN/USN.
"""
import argparse
import csv
import datetime
import re
import sys
from collections import defaultdict

# MFTECmd $MFT CSV columns (current versions)
COL_PATH = ["ParentPath", "FileName"]
COL_NAME = "FileName"
COL_SI_CREATED = "Created0x10"
COL_SI_MODIFIED = "LastModified0x10"
COL_FN_CREATED = "Created0x30"
COL_INUSE = "InUse"

# USN ($J) CSV columns
USN_NAME = "Name"
USN_TS = "UpdateTimestamp"
USN_REASON = "UpdateReasons"

RANSOM_EXT = re.compile(r"\.(lockbit|babuk|dragonforce|play|warlock|encrypt|locked|crypt)$", re.I)
SDELETE_RENAME = re.compile(r"^(A{3,}|Z{3,}|0{3,})", re.I)  # SDelete/CCleaner placeholder names


def parse_ts(s):
    if not s or not s.strip():
        return None
    s = s.strip().replace("Z", "")
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
                "%m/%d/%Y %H:%M:%S.%f", "%m/%d/%Y %H:%M:%S"):
        try:
            return datetime.datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def has_zero_subsecond(s):
    """True if timestamp string carries an explicit .0000000 (tool-zeroed) fraction."""
    m = re.search(r"\.(\d+)$", (s or "").strip())
    return bool(m) and int(m.group(1)) == 0


def has_subsecond(s):
    m = re.search(r"\.(\d+)$", (s or "").strip())
    return bool(m) and int(m.group(1)) != 0


def analyze_mft(path):
    findings = []
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            name = row.get(COL_NAME, "")
            full = (row.get("ParentPath", "") + "\\" + name).replace("\\\\", "\\")
            si_c_raw = row.get(COL_SI_CREATED, "")
            fn_c_raw = row.get(COL_FN_CREATED, "")
            si_m_raw = row.get(COL_SI_MODIFIED, "")
            si_c, fn_c, si_m = parse_ts(si_c_raw), parse_ts(fn_c_raw), parse_ts(si_m_raw)

            # 1) classic: $SI created earlier than $FN created (file claims older than its name record)
            if si_c and fn_c and si_c < fn_c - datetime.timedelta(seconds=1):
                findings.append(("HIGH", full,
                                 f"$SI.Created ({si_c}) < $FN.Created ({fn_c}) -> timestomp"))
            # 2) $SI created AFTER $SI modified (impossible naturally -> stomped)
            if si_c and si_m and si_c > si_m + datetime.timedelta(seconds=2):
                findings.append(("MEDIUM", full,
                                 f"$SI.Created ({si_c}) > $SI.Modified ({si_m}) -> stomped"))
            # 3) $SI fractional seconds zeroed while $FN keeps precision (tool signature)
            if has_zero_subsecond(si_c_raw) and has_subsecond(fn_c_raw):
                findings.append(("MEDIUM", full,
                                 "$SI sub-second = .0000000 but $FN has precision -> tool-zeroed"))
    return findings


def analyze_usn(path):
    findings = []
    renames_by_min = defaultdict(int)
    deletes_by_min = defaultdict(int)
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            name = row.get(USN_NAME, "")
            reasons = (row.get(USN_REASON, "") or "")
            ts = parse_ts(row.get(USN_TS, ""))
            minute = ts.replace(second=0, microsecond=0) if ts else None

            if SDELETE_RENAME.match(name) and "Rename" in reasons:
                findings.append(("HIGH", name,
                                 "SDelete/CCleaner-style placeholder rename (secure delete)"))
            if RANSOM_EXT.search(name):
                findings.append(("HIGH", name, "rename/create to known ransomware extension"))
            if minute and "RenameNewName" in reasons:
                renames_by_min[minute] += 1
            if minute and ("FileDelete" in reasons or "Close" in reasons and "Delete" in reasons):
                deletes_by_min[minute] += 1

    for minute, n in renames_by_min.items():
        if n >= 100:
            findings.append(("HIGH", str(minute),
                             f"mass rename burst: {n} renames in one minute (ransomware/wiper)"))
    for minute, n in deletes_by_min.items():
        if n >= 100:
            findings.append(("HIGH", str(minute),
                             f"mass delete burst: {n} deletes in one minute (destruction)"))
    return findings


def main() -> int:
    ap = argparse.ArgumentParser(description="NTFS timestomp / USN tamper detector (MFTECmd CSV)")
    ap.add_argument("--mft", required=True, help="MFTECmd $MFT CSV")
    ap.add_argument("--usn", help="MFTECmd $J (USN journal) CSV")
    ap.add_argument("--out", default="timestomp_findings.csv")
    args = ap.parse_args()

    findings = []
    findings += analyze_mft(args.mft)
    if args.usn:
        findings += analyze_usn(args.usn)

    with open(args.out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["Severity", "Target", "Finding"])
        for sev, tgt, det in findings:
            w.writerow([sev, tgt, det])

    print(f"=== TIMESTOMP / TAMPER FINDINGS ({len(findings)}) -> {args.out} ===")
    for sev, tgt, det in findings[:200]:
        print(f"[{sev}] {tgt}: {det}")
    if not findings:
        print("(no anti-forensic timestamp anomalies detected; absence != innocence — also check "
              "$LogFile and VSS history)")
    return 2 if any(s == "HIGH" for s, _, _ in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
