#!/usr/bin/env bash
# evtx_hunt.sh - Windows event-log fast-triage pipeline: Chainsaw + Hayabusa Sigma hunt and timeline.
#
# Runs the two leading Rust EVTX engines over a directory of .evtx files and produces:
#   - chainsaw Sigma hunt CSV (high/critical, stable rules)
#   - hayabusa super-verbose timeline CSV (Timeline Explorer / Timesketch ready)
#   - an EventRecordID gap report per channel (selective-deletion anti-forensics tell)
#
# Usage:
#   ./evtx_hunt.sh -d /evidence/.../winevt/Logs -o /evidence/timeline \
#                  [-s /opt/sigma/rules/windows] [--start "2026-06-01 00:00:00 +00:00"] \
#                  [--end "2026-06-15 00:00:00 +00:00"]
#
# Dependencies: chainsaw (v2), hayabusa (v3), a cloned SigmaHQ/sigma ruleset (chainsaw v2 no longer
#   bundles rules). python3 for the gap report. Tools must be on PATH or set CHAINSAW/HAYABUSA env.
# Notes: read-only over collected EVTX. If logs were cleared (EventID 1102/104), pull EVTX from VSS
#   or the disk image first (see references/anti-forensics-detection.md). On a live host prefer
#   Hayabusa Live Response packages to minimise disk writes.
set -u

CHAINSAW="${CHAINSAW:-chainsaw}"
HAYABUSA="${HAYABUSA:-hayabusa}"
SIGMA=""
EVTXDIR=""
OUT=""
START=""
END=""

usage() { grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    -d) EVTXDIR="$2"; shift 2 ;;
    -o) OUT="$2"; shift 2 ;;
    -s) SIGMA="$2"; shift 2 ;;
    --start) START="$2"; shift 2 ;;
    --end) END="$2"; shift 2 ;;
    -h|--help) usage 0 ;;
    *) echo "unknown arg: $1"; usage 1 ;;
  esac
done

[ -z "$EVTXDIR" ] && { echo "[!] -d EVTX dir required"; usage 1; }
[ -d "$EVTXDIR" ] || { echo "[!] not a directory: $EVTXDIR"; exit 1; }
[ -z "$OUT" ] && OUT="./evtx_out_$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT"

echo "=== EVTX hunt  src=$EVTXDIR  out=$OUT ==="

# 1) Chainsaw Sigma hunt (high/critical, stable). Needs a Sigma ruleset.
if command -v "$CHAINSAW" >/dev/null 2>&1; then
  if [ -n "$SIGMA" ] && [ -d "$SIGMA" ]; then
    MAPPING="$(dirname "$(command -v "$CHAINSAW")")/mappings/sigma-event-logs-all.yml"
    [ -f "$MAPPING" ] || MAPPING="mappings/sigma-event-logs-all.yml"
    echo "[*] chainsaw hunt (Sigma: $SIGMA)"
    "$CHAINSAW" hunt "$EVTXDIR" -s "$SIGMA" --mapping "$MAPPING" \
      --level high --status stable --csv -o "$OUT/chainsaw" 2>"$OUT/chainsaw.log" \
      || echo "[!] chainsaw hunt returned non-zero (see chainsaw.log)"
  else
    echo "[*] chainsaw hunt (built-in rules, no -s Sigma dir given)"
    "$CHAINSAW" hunt "$EVTXDIR" --csv -o "$OUT/chainsaw" 2>"$OUT/chainsaw.log" \
      || echo "[!] chainsaw hunt non-zero"
  fi
else
  echo "[!] chainsaw not found — skipping (install WithSecureLabs/chainsaw v2)"
fi

# 2) Hayabusa timeline (super-verbose, RFC3339, optional incident window).
if command -v "$HAYABUSA" >/dev/null 2>&1; then
  echo "[*] hayabusa csv-timeline"
  HB_ARGS=(csv-timeline -d "$EVTXDIR" -p super-verbose -o "$OUT/hayabusa_timeline.csv"
           --RFC-3339 --no-wizard --quiet)
  [ -n "$START" ] && HB_ARGS+=(--timeline-start "$START")
  [ -n "$END" ]   && HB_ARGS+=(--timeline-end   "$END")
  "$HAYABUSA" "${HB_ARGS[@]}" 2>"$OUT/hayabusa.log" || echo "[!] hayabusa non-zero (see hayabusa.log)"
  "$HAYABUSA" metrics -d "$EVTXDIR" -o "$OUT/hayabusa_metrics.csv" >/dev/null 2>&1 || true
else
  echo "[!] hayabusa not found — skipping (install Yamato-Security/hayabusa v3)"
fi

# 3) Log-clearing / EventRecordID gap detection (anti-forensics).
#    Detect EventID 1102 (Security cleared) / 104 (System cleared) and record-id gaps.
python3 - "$OUT" "$EVTXDIR" <<'PY'
import sys, glob, os, re, subprocess, json
out, evtxdir = sys.argv[1], sys.argv[2]
findings = []

# If a hayabusa/chainsaw CSV exists, scan for clear events cheaply.
for csv in glob.glob(os.path.join(out, "*.csv")) + glob.glob(os.path.join(out, "chainsaw*", "*.csv")):
    try:
        txt = open(csv, encoding="utf-8", errors="ignore").read()
    except OSError:
        continue
    if re.search(r'\b1102\b', txt) and re.search(r'(?i)log.*clear|audit.*clear', txt):
        findings.append({"sev": "HIGH", "evt": csv, "detail": "EventID 1102 (Security log cleared)"})
    if re.search(r'\b104\b', txt) and re.search(r'(?i)log.*clear', txt):
        findings.append({"sev": "HIGH", "evt": csv, "detail": "EventID 104 (a log was cleared)"})

# Optional: if evtx_dump (the python lib CLI) is present, do a true record-id gap check.
if any(os.access(os.path.join(p, "evtx_dump"), os.X_OK)
       for p in os.environ.get("PATH", "").split(os.pathsep) if p):
    for f in glob.glob(os.path.join(evtxdir, "*.evtx")):
        try:
            raw = subprocess.run(["evtx_dump", "-o", "jsonl", f],
                                 capture_output=True, text=True, timeout=600).stdout
        except Exception:
            continue
        ids = sorted(int(m) for m in re.findall(r'"event_record_id"\s*:\s*(\d+)', raw))
        gaps = [(a, b) for a, b in zip(ids, ids[1:]) if b - a > 1]
        if gaps:
            findings.append({"sev": "MEDIUM", "evt": os.path.basename(f),
                             "detail": f"EventRecordID gaps (possible selective deletion): {gaps[:10]}"})

json.dump(findings, open(os.path.join(out, "anti_forensics.json"), "w"), indent=2)
print("\n=== ANTI-FORENSICS / LOG-CLEAR CHECK ===")
if not findings:
    print("(no clear/gaps detected in available output)")
for x in findings:
    print(f"[{x['sev']}] {x['detail']}  <- {x['evt']}")
PY

echo
echo "=== DONE ==="
echo "  Sigma hits : $OUT/chainsaw*"
echo "  Timeline   : $OUT/hayabusa_timeline.csv  (open in Timeline Explorer or import to Timesketch)"
echo "  Anti-forensics: $OUT/anti_forensics.json"
