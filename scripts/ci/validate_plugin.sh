#!/usr/bin/env bash
# validate_plugin.sh - run the AUTHORITATIVE Claude Code plugin validator locally / at release.
#
# `claude plugin validate` is the source of truth for manifest + skill/agent/command frontmatter
# and catches version-specific rules the pure-stdlib gate (check_plugin_manifest.py) cannot know
# about. It needs the `claude` CLI, so it is a LOCAL / release-checklist step, not a CI gate.
#
# Usage:  scripts/ci/validate_plugin.sh [--strict]
#   --strict  treat warnings as errors (note: a root CLAUDE.md always warns "not loaded as plugin
#             context" - the plugin ships context via the SessionStart dispatcher skill instead, so
#             that warning is expected and CLAUDE.md is kept for in-repo contributors).
#
# Exit: non-zero if either manifest fails validation.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STRICT="${1:-}"

if ! command -v claude >/dev/null 2>&1; then
  echo "validate_plugin.sh: 'claude' CLI not found - install Claude Code to run the authoritative validator" >&2
  echo "  (CI still enforces scripts/ci/check_plugin_manifest.py, the stdlib gate)" >&2
  exit 127
fi

rc=0
echo "== marketplace manifest =="
claude plugin validate $STRICT "$ROOT/.claude-plugin/marketplace.json" || rc=$?
echo "== plugin manifest + components =="
claude plugin validate $STRICT "$ROOT/.claude-plugin/plugin.json" || rc=$?

exit "$rc"
