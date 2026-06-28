#!/usr/bin/env bash
#
# provenance_verify.sh - Defensive gate: verify SLSA build provenance + cosign keyless signature
# for a container image (or artifact) BEFORE promoting/deploying it. Run this in a release job or
# admission step; a non-zero exit must block promotion.
#
# It enforces that the artifact was built:
#   - by the expected SLSA builder (slsa-github-generator),
#   - from the expected source repo + ref,
#   - and signed by the expected workflow identity via Sigstore (Fulcio cert + Rekor log).
#
# Usage:
#   provenance_verify.sh --image ghcr.io/org/app:tag --repo org/app
#   provenance_verify.sh --image ghcr.io/org/app@sha256:DIGEST --repo org/app \
#       --workflow .github/workflows/release.yml \
#       --builder 'https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.0.0'
#
# Deps: cosign (>=2), slsa-verifier, crane OR docker (to resolve a tag to a digest). jq optional.
set -euo pipefail

IMAGE="" ; REPO="" ; WORKFLOW=".github/workflows/release.yml"
BUILDER='https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.0.0'
ISSUER='https://token.actions.githubusercontent.com'
REKOR='https://rekor.sigstore.dev'

while [ $# -gt 0 ]; do
  case "$1" in
    --image)    IMAGE="$2"; shift 2 ;;
    --repo)     REPO="$2"; shift 2 ;;
    --workflow) WORKFLOW="$2"; shift 2 ;;
    --builder)  BUILDER="$2"; shift 2 ;;
    --issuer)   ISSUER="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
[ -n "$IMAGE" ] && [ -n "$REPO" ] || { echo "usage: --image <ref> --repo <org/name>" >&2; exit 2; }

command -v cosign        >/dev/null || { echo "cosign not installed" >&2; exit 3; }
command -v slsa-verifier >/dev/null || { echo "slsa-verifier not installed" >&2; exit 3; }

# 1. Resolve a tag reference to an immutable digest (never verify a mutable tag).
if echo "$IMAGE" | grep -q '@sha256:'; then
  IMAGE_DIGEST="$IMAGE"
else
  if command -v crane >/dev/null; then
    DIG=$(crane digest "$IMAGE")
  elif command -v docker >/dev/null; then
    docker pull -q "$IMAGE" >/dev/null
    DIG=$(docker buildx imagetools inspect "$IMAGE" --format '{{.Manifest.Digest}}' 2>/dev/null \
          || docker inspect --format '{{index .RepoDigests 0}}' "$IMAGE" | sed 's/.*@//')
  else
    echo "need crane or docker to resolve tag->digest" >&2; exit 3
  fi
  BASE="${IMAGE%%:*}"
  IMAGE_DIGEST="${BASE}@${DIG}"
fi
echo "[*] verifying immutable ref: $IMAGE_DIGEST"

# 2. SLSA provenance: must come from $REPO via the trusted builder.
echo "[*] slsa-verifier: source=github.com/$REPO builder=$BUILDER"
if slsa-verifier verify-image "$IMAGE_DIGEST" \
      --source-uri "github.com/$REPO" \
      --builder-id "$BUILDER"; then
  echo "[+] SLSA provenance OK"
else
  echo "[!] SLSA provenance verification FAILED -- BLOCK promotion" >&2; exit 1
fi

# 3. Cosign keyless attestation: identity must match the expected release workflow + OIDC issuer.
IDENTITY_RE="^https://github.com/${REPO}/\\.github/workflows/$(basename "$WORKFLOW")@refs/"
echo "[*] cosign verify-attestation identity~=$IDENTITY_RE issuer=$ISSUER"
if COSIGN_EXPERIMENTAL=1 cosign verify-attestation "$IMAGE_DIGEST" \
      --type slsaprovenance \
      --certificate-identity-regexp "$IDENTITY_RE" \
      --certificate-oidc-issuer "$ISSUER" \
      --rekor-url "$REKOR" >/dev/null 2>&1; then
  echo "[+] cosign keyless signature + Rekor entry OK"
else
  echo "[!] cosign attestation verification FAILED -- BLOCK promotion" >&2; exit 1
fi

echo "[+] ALL GATES PASSED: $IMAGE_DIGEST is verified -- safe to promote"
