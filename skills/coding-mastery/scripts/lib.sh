#!/usr/bin/env bash
# lib.sh — shared helpers sourced by the toolkit's bash scripts.
# Goal: pipelines DEGRADE GRACEFULLY on partially-provisioned hosts (skip, don't crash),
# and logging/scope helpers are consistent across scripts.
#
#   source "$(dirname "$0")/../../coding-mastery/scripts/lib.sh"
#   _have nuclei || _skip "nuclei not installed — skipping nuclei stage"
#   _need subfinder || return 0
#
# Sourcing is idempotent.

[ -n "${_OFFCLAUDE_LIB_SH:-}" ] && return 0
_OFFCLAUDE_LIB_SH=1

# --- logging (stderr, so stdout stays machine-parseable) ---
_log()  { printf '[*] %s\n'  "$*" >&2; }
_ok()   { printf '[+] %s\n'  "$*" >&2; }
_warn() { printf '[!] %s\n'  "$*" >&2; }
_err()  { printf '[x] %s\n'  "$*" >&2; }
_skip() { printf '[skip] %s\n' "$*" >&2; }

# --- dependency checks ---
# _have CMD  -> 0 if CMD is on PATH, 1 otherwise (silent).
_have() { command -v "$1" >/dev/null 2>&1; }

# _need CMD  -> 0 if present; else prints a skip notice and returns 1 (skip-not-fail).
_need() {
  if _have "$1"; then return 0; fi
  _skip "$1 not found on PATH — skipping this stage (install: ${2:-$1})"
  return 1
}

# _require CMD -> hard requirement; exits non-zero if missing (use sparingly).
_require() {
  if _have "$1"; then return 0; fi
  _err "required tool '$1' not found on PATH — aborting"
  exit 127
}

# --- scope guard bridge: refuse to touch an out-of-scope target ---
# _in_scope TARGET SCOPE_JSON -> 0 if in-scope, 1 otherwise. No scope file => allow + warn.
_in_scope() {
  local target="$1" scope="${2:-${SCOPE_FILE:-}}"
  local guard
  guard="$(dirname "${BASH_SOURCE[0]}")/_lib/scope_guard.py"
  if [ -z "$scope" ] || [ ! -f "$scope" ]; then
    _warn "no scope.json provided (SCOPE_FILE unset) — proceeding WITHOUT scope enforcement"
    return 0
  fi
  if [ ! -f "$guard" ]; then
    _warn "scope_guard.py not found — proceeding without enforcement"
    return 0
  fi
  if python "$guard" check "$target" --scope "$scope" >/dev/null 2>&1; then
    return 0
  fi
  _err "OUT-OF-SCOPE: $target (per $scope) — refusing"
  return 1
}
