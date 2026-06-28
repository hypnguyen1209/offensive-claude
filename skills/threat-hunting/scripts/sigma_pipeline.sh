#!/usr/bin/env bash
# =============================================================================
# sigma_pipeline.sh - Detection-as-Code pipeline: lint -> convert -> artifact.
#
# Lints every Sigma rule (via dac_validate.py) then compiles the rule set to one
# or more SIEM backends with sigma-cli, writing per-backend artifacts. Designed to
# be the single command a CI job runs.
#
# USAGE:
#   ./sigma_pipeline.sh <rules_dir> [out_dir] [backend1 backend2 ...]
#   ./sigma_pipeline.sh ./rules ./build splunk microsoft365defender elasticsearch
#   (default backends: splunk microsoft365defender elasticsearch)
#
# DEPENDENCIES:
#   python3, pyyaml, sigma-cli and backend plugins:
#     pip install sigma-cli pysigma-backend-splunk \
#       pysigma-backend-microsoft365defender pysigma-backend-elasticsearch \
#       pysigma-pipeline-sysmon pyyaml
#
# EXIT: non-zero if lint finds errors or any backend conversion fails (CI gate).
# Defensive detection-engineering tooling. Authorized use only.
# =============================================================================
set -euo pipefail

RULES_DIR="${1:?usage: sigma_pipeline.sh <rules_dir> [out_dir] [backends...]}"
OUT_DIR="${2:-./build}"
shift || true
shift || true
BACKENDS=("$@")
if [ "${#BACKENDS[@]}" -eq 0 ]; then
  BACKENDS=(splunk microsoft365defender elasticsearch)
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$OUT_DIR"

echo "[*] Stage 1/3 - lint $RULES_DIR (Detection-as-Code policy)"
python3 "$SCRIPT_DIR/dac_validate.py" "$RULES_DIR" --fail-on-error

# Map a sensible default pipeline per backend (sysmon mapping for windows backends).
pipeline_for() {
  case "$1" in
    splunk|elasticsearch) echo "sysmon" ;;
    *) echo "" ;;
  esac
}

echo "[*] Stage 2/3 - convert to backends: ${BACKENDS[*]}"
fail=0
for be in "${BACKENDS[@]}"; do
  pl="$(pipeline_for "$be")"
  out="$OUT_DIR/detections_${be}.txt"
  echo "    -> $be (pipeline='${pl:-none}') => $out"
  if [ -n "$pl" ]; then
    sigma convert -t "$be" -p "$pl" "$RULES_DIR" -o "$out" || fail=1
  else
    sigma convert -t "$be" "$RULES_DIR" -o "$out" || fail=1
  fi
done

echo "[*] Stage 3/3 - summary"
ls -la "$OUT_DIR"
if [ "$fail" -ne 0 ]; then
  echo "[!] One or more backend conversions failed." >&2
  exit 1
fi
echo "[+] Pipeline complete. Artifacts in $OUT_DIR/"
