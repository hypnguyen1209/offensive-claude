#!/usr/bin/env bash
# ebpf_rootkit_hunt.sh - Linux eBPF / kernel rootkit hunter (LinkPro-aware).
#
# Hunts for eBPF-based rootkits (TripleCross/ebpfkit/boopkit/pamspy class, and the in-the-wild
# LinkPro implant - Synacktiv Oct 2025) plus classic kernel-module hiding. Designed to run on a
# LIVE host during IR; emphasises checks that DON'T solely trust userland tools the rootkit blinds.
#
# Usage:
#   sudo ./ebpf_rootkit_hunt.sh [-o OUTDIR] [-b baseline_progs.txt]
#     -o OUTDIR   write evidence/output here (default: ./ebpf_hunt_<host>_<ts>)
#     -b FILE     compare `bpftool prog show` against a known-good baseline file
#
# Dependencies: bash, coreutils, bpftool (preferred), ss, grep. Optional: libbpf-tools.
# Notes: bpftool/ss/ps can be LIED to by an active rootkit (LinkPro hides its own BPF progs via
#   bpf_override_return). For ground truth, also acquire RAM out-of-band and run Volatility 3
#   linux.ebpf (see references/memory-forensics.md). This script flags signals, not verdicts.
set -u

OUT=""
BASELINE=""
while getopts "o:b:h" opt; do
  case "$opt" in
    o) OUT="$OPTARG" ;;
    b) BASELINE="$OPTARG" ;;
    h) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "bad option"; exit 1 ;;
  esac
done

TS="$(date -u +%Y%m%dT%H%M%SZ)"
HOST="$(hostname 2>/dev/null || echo unknown)"
[ -z "$OUT" ] && OUT="./ebpf_hunt_${HOST}_${TS}"
mkdir -p "$OUT"
REPORT="$OUT/findings.txt"
: > "$REPORT"

flag() { echo "[FLAG][$1] $2" | tee -a "$REPORT"; }
info() { echo "[INFO] $1"; }

[ "$(id -u)" -ne 0 ] && echo "[WARN] not root — many checks need CAP_SYS_ADMIN/CAP_BPF" >&2

echo "=== eBPF/rootkit hunt  host=$HOST  $TS ===" | tee -a "$REPORT"

# 1) Enumerate loaded BPF programs (may be incomplete if hidden — that's why we cross-check).
if command -v bpftool >/dev/null 2>&1; then
  bpftool prog show > "$OUT/bpftool_prog.txt" 2>/dev/null
  bpftool map  show > "$OUT/bpftool_map.txt"  2>/dev/null   # LinkPro forgets to hide maps/links!
  bpftool link show > "$OUT/bpftool_link.txt" 2>/dev/null
  info "bpftool prog/map/link dumped"

  # 1a) Strong IOC: bpf_override_return inside any xlated program (file-hiding mechanism).
  while read -r id _; do
    [ -z "$id" ] && continue
    if bpftool prog dump xlated id "$id" 2>/dev/null | grep -qi 'bpf_override_return'; then
      flag HIGH "BPF prog id=$id uses bpf_override_return (kernel-hiding rootkit IOC)"
    fi
  done < <(bpftool prog show 2>/dev/null | grep -oE '^[0-9]+:' | tr -d ':')

  # 1b) XDP/TC programs are LinkPro's 'Knock' module surface.
  grep -Ei 'xdp|sched_cls|sched_act|tc' "$OUT/bpftool_prog.txt" 2>/dev/null \
    && flag MEDIUM "XDP/TC BPF program(s) present — inspect for magic-packet (LinkPro Knock)"

  # 1c) Baseline diff (program hidden from live tool shows up as MISSING vs baseline).
  if [ -n "$BASELINE" ] && [ -f "$BASELINE" ]; then
    if ! diff -q <(sort "$BASELINE") <(sort "$OUT/bpftool_prog.txt") >/dev/null 2>&1; then
      flag MEDIUM "bpftool prog list differs from baseline ($BASELINE) — possible hidden prog"
      diff <(sort "$BASELINE") <(sort "$OUT/bpftool_prog.txt") > "$OUT/baseline_diff.txt" 2>&1
    fi
  fi

  # 1d) maps/links present but prog list suspiciously short -> hidden-prog tell (LinkPro gap).
  nprog=$(grep -cE '^[0-9]+:' "$OUT/bpftool_prog.txt" 2>/dev/null || echo 0)
  nlink=$(grep -cE '^[0-9]+:' "$OUT/bpftool_link.txt" 2>/dev/null || echo 0)
  if [ "$nlink" -gt "$nprog" ]; then
    flag HIGH "More BPF links ($nlink) than progs ($nprog) — programs likely hidden (LinkPro-style)"
  fi
else
  flag MEDIUM "bpftool not installed — cannot enumerate BPF; acquire RAM + run vol3 linux.ebpf"
fi

# 2) LinkPro userland-fallback: /etc/ld.so.preload hooking + libld.so.
if [ -s /etc/ld.so.preload ]; then
  flag HIGH "/etc/ld.so.preload is non-empty: $(tr '\n' ' ' </etc/ld.so.preload)"
  cp /etc/ld.so.preload "$OUT/ld.so.preload" 2>/dev/null
fi
find / -xdev -name 'libld.so' 2>/dev/null | while read -r p; do
  flag HIGH "found suspicious shared object: $p (LinkPro userland hook)"
done

# 3) Network discrepancy: ss (netlink) vs /proc/net (libld.so hook filters /proc/net lines).
ss -tanp 2>/dev/null > "$OUT/ss.txt"
ss_ports=$(awk 'NR>1{print $4}' "$OUT/ss.txt" | sed 's/.*://' | sort -u)
proc_ports=$(awk 'NR>1{print strtonum("0x" substr($2, index($2,":")+1))}' /proc/net/tcp 2>/dev/null | sort -u)
# LinkPro default listener port 2233 / magic SYN window 54321
if echo "$ss_ports" | grep -qx 2233; then
  flag HIGH "ss shows port 2233 (LinkPro default internal listener)"
fi
if ! awk 'NR>1{print strtonum("0x" substr($2, index($2,":")+1))}' /proc/net/tcp 2>/dev/null \
      | grep -qx 2233 && echo "$ss_ports" | grep -qx 2233; then
  flag HIGH "port 2233 visible to ss(netlink) but hidden from /proc/net/tcp — userland hook active"
fi

# 4) Persistence masquerade: fake systemd-resolveld (typosquat of systemd-resolved) + staging dir.
if [ -e /etc/systemd/system/systemd-resolveld.service ] \
   || systemctl cat systemd-resolveld.service >/dev/null 2>&1; then
  flag HIGH "systemd-resolveld.service present (LinkPro persistence typosquat of systemd-resolved)"
fi
for d in /usr/lib/.system /usr/lib/.tmp~data; do
  [ -e "$d" ] && flag HIGH "LinkPro staging path present: $d"
done
find / -xdev \( -name '.tmp~data*' -o -name '*.tmp~data.resolveld' \) 2>/dev/null \
  | while read -r p; do flag HIGH "LinkPro artifact: $p"; done

# 5) Classic kernel-module hiding: /proc/modules vs /sys/module mismatch.
proc_mods=$(awk '{print $1}' /proc/modules 2>/dev/null | sort -u)
sys_mods=$(ls /sys/module 2>/dev/null | sort -u)
comm -13 <(echo "$proc_mods") <(echo "$sys_mods") > "$OUT/module_only_in_sysfs.txt" 2>/dev/null
if [ -s "$OUT/module_only_in_sysfs.txt" ]; then
  flag MEDIUM "module(s) in /sys/module but not /proc/modules (possible hiding):"
  sed 's/^/    /' "$OUT/module_only_in_sysfs.txt" | tee -a "$REPORT"
fi

# 6) Recovered bash history hint (cleared on disk but may persist in RAM — note for vol3 linux.bash).
[ ! -s "$HOME/.bash_history" ] && info "current user .bash_history empty/missing -> check vol3 linux.bash"

echo
echo "=== SUMMARY (full report: $REPORT) ==="
if grep -q '^\[FLAG\]' "$REPORT"; then
  grep '^\[FLAG\]' "$REPORT"
  echo "[!] Signals found. Acquire RAM out-of-band (LiME RO / hypervisor snapshot) and confirm with"
  echo "    Volatility 3 linux.ebpf + YARA (MAL_LinkPro_*). Do NOT trust on-host tools alone."
  exit 2
else
  echo "No eBPF/rootkit signals from live checks. NOTE: a competent rootkit hides from these —"
  echo "absence of signal is not proof of clean. Out-of-band memory analysis still recommended."
  exit 0
fi
