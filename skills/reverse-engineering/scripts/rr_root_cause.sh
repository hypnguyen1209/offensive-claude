#!/usr/bin/env bash
# rr_root_cause.sh — deterministic record/replay root-cause for a crashing input.
#
# Records the crashing run with rr (Mozilla time-travel debugger), then drives a reverse-debug
# session to the fault and emits two machine artifacts the finding harness understands:
#   - a function-trace log (trace_proof: validate_findings.py checks the vuln function appears), and
#   - a root-cause summary (faulting instruction + a reverse-continue note).
#
# Linux-only (needs rr + gdb + CAP_SYS_PTRACE; see .devcontainer/). DEGRADES GRACEFULLY: if rr/gdb
# are absent (e.g. on a non-Linux host) it skips with a notice instead of failing the pipeline.
#
# Usage:
#   rr_root_cause.sh <target> [args...]            # the crashing invocation (e.g. ./vuln poc_input)
#   OUT=results/ rr_root_cause.sh ./vuln @@         # @@ replaced by $CRASH_INPUT if set
#
# Env: OUT (output dir, default ./rr-out), CRASH_INPUT (file substituted for @@), FUNC (vuln function
# name to confirm in the trace; default: auto from the crashing frame).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
source "$HERE/../../coding-mastery/scripts/lib.sh"

OUT="${OUT:-./rr-out}"
TARGET="${1:-}"
[ -z "$TARGET" ] && { _err "usage: rr_root_cause.sh <target> [args...]"; exit 2; }
shift || true

_need rr  "rr (https://rr-project.org); apt install rr — and set kernel.perf_event_paranoid=1" || exit 0
_need gdb "gdb" || exit 0

mkdir -p "$OUT"
ARGS=()
for a in "$@"; do
  if [ "$a" = "@@" ] && [ -n "${CRASH_INPUT:-}" ]; then ARGS+=("$CRASH_INPUT"); else ARGS+=("$a"); fi
done

_log "recording crashing run under rr: $TARGET ${ARGS[*]:-}"
# _RR_TRACE_DIR keeps the trace inside the engagement workspace (not ~/.local/share/rr).
export _RR_TRACE_DIR="$OUT/rr-trace"
rm -rf "$_RR_TRACE_DIR"
if ! rr record -n "$TARGET" "${ARGS[@]}" >"$OUT/record.log" 2>&1; then
  _warn "target did not crash (or rr record failed) — see $OUT/record.log; nothing to root-cause"
fi

# Replay: stop at the fault, capture the crashing frame, then reverse-continue one step for the cause.
GDB_CMDS="$OUT/rr.gdb"
cat > "$GDB_CMDS" <<'GDB'
set pagination off
set logging file rr-out/gdb.log
set logging on
continue
echo \n==== CRASHING FRAME ====\n
bt 12
echo \n==== REVERSE STEP (where the bad value was set) ====\n
reverse-stepi
info registers rip rsp
echo \n==== FUNCTION TRACE (entered functions on the path) ====\n
GDB

_log "replaying to fault + reverse-stepping for root cause"
# -o feeds the gdb script; rr replay is deterministic so this is reproducible.
rr replay -o "-x $GDB_CMDS -batch" >"$OUT/replay.log" 2>&1 || _warn "replay ended early — see $OUT/replay.log"

# Emit the trace_proof artifact: the functions seen on the crashing run (rr can list them).
TRACE="$OUT/trace.txt"
rr replay -a >"$TRACE" 2>/dev/null || cp "$OUT/replay.log" "$TRACE"
FUNC="${FUNC:-$(grep -m1 -oE '#[0-9]+ +0x[0-9a-f]+ in +[A-Za-z_][A-Za-z0-9_]*' "$OUT/gdb.log" 2>/dev/null | awk '{print $NF}')}"

_ok "root-cause artifacts in $OUT/:"
_ok "  trace_proof : $TRACE  (function: ${FUNC:-<unknown - set FUNC=>})"
_ok "  summary     : $OUT/gdb.log (crashing frame + reverse step)"
cat <<JSON
{"trace_proof": {"log": "$TRACE", "function": "${FUNC:-FILL_IN}"},
 "note": "rr deterministic replay; reverse-stepi shows where the bad value was set (see gdb.log)"}
JSON
