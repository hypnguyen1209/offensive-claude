#!/bin/sh
# cap_suid_hunter.sh - Triage SUID/SGID binaries, file capabilities, and sudo rights, ranking only
#                      the entries that map to a GTFOBins escape (skips the dozens of benign set-id bins).
#
# USAGE:
#   ./cap_suid_hunter.sh             # full triage (SUID/SGID + caps + sudo -l)
#   ./cap_suid_hunter.sh --path      # low-noise: scan only $PATH dirs for SUID/SGID (no full FS walk)
#   ./cap_suid_hunter.sh --no-find   # skip SUID find entirely (caps + sudo only)
#
# DEPENDENCIES: POSIX sh, find, getcap (libcap), sudo (optional). No network. Pure read-only.
# OPSEC: a full `find / -perm -4000` triggers EDR file-scan heuristics. Use --path on monitored hosts.

GREEN='\033[92m'; RED='\033[91m'; YEL='\033[93m'; CYN='\033[96m'; RST='\033[0m'
[ -t 1 ] || { GREEN=''; RED=''; YEL=''; CYN=''; RST=''; }

# GTFOBins-able binaries (basenames). Curated subset of https://gtfobins.github.io
GTFO="aa-exec ab ar arj as ascii-xfr ash awk base32 base64 basenc basez bash bridge busctl busybox \
byebug bundle cabal capsh cat chmod chown chroot cmp comm cp cpio cpulimit crash csh csvtool cupsfilter \
curl dash date dd dialog diff dig dmsetup docker dosbox ed emacs env eqn expand expect file find fish \
flock fmt fold gawk gcc gdb genie genisoimage gimp grep gtester gzip hd head hexdump highlight hping3 \
iconv install ionice ip ispell jjs join journalctl jq jrunscript ksh ksshell ld.so ldconfig less logsave \
look lua make man mawk more mosquitto msgattrib msgcat msgconv msgfilter msgmerge msguniq multitime mv \
mysql nano nawk nc ncftp nft nice nl nmap node nohup npm octave od openssl openvpn pandoc paste pdftex \
perl pg php pic pico pidstat pip posh pr puppet python python2 python3 rake readelf red redcarpet restic \
rev rlwrap rpm rpmquery rsync ruby run-mailcap run-parts rview rvim sash scp screen script sed service \
setarch sftp sg shuf slsh smbclient socat soelim sort split sqlite3 ss ssh start-stop-daemon stdbuf \
strace strings sysctl systemctl tac tail tar taskset tbl tclsh tcpdump tee telnet tex tftp tic time \
timeout tmux top troff ul unexpand uniq unshare unzip update-alternatives uudecode uuencode vagrant \
valgrind vi view vim vimdiff watch wc wget whiptail wireshark xargs xdotool xelatex xetex xmodmap xmore \
xpad xxd xz yarn yash yelp zip zsh zsoelim zypper"

DANGEROUS_CAPS="cap_setuid cap_setgid cap_dac_read_search cap_dac_override cap_sys_admin cap_sys_ptrace \
cap_chown cap_fowner cap_sys_module cap_sys_rawio cap_net_admin cap_net_raw cap_sys_chroot"

is_gtfo() {
  b="$1"
  for g in $GTFO; do [ "$b" = "$g" ] && return 0; done
  return 1
}

MODE="full"
for a in "$@"; do
  case "$a" in
    --path) MODE="path" ;;
    --no-find) MODE="nofind" ;;
  esac
done

printf "%bcap_suid_hunter.sh%b  mode=%s  $(date -u '+%Y-%m-%dT%H:%M:%SZ')\n" "$CYN" "$RST" "$MODE"
printf "uid: %s\n" "$(id)"

# ---- SUID / SGID ----------------------------------------------------------
if [ "$MODE" != "nofind" ]; then
  printf "\n%b=== SUID / SGID (GTFOBins-flagged) ===%b\n" "$CYN" "$RST"
  if [ "$MODE" = "path" ]; then
    DIRS=$(printf '%s' "$PATH" | tr ':' ' ')
    SUID_LIST=$(find $DIRS -maxdepth 1 \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null)
  else
    SUID_LIST=$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null)
  fi

  for f in $SUID_LIST; do
    b=$(basename "$f")
    perms=$(ls -l "$f" 2>/dev/null | awk '{print $1, $3, $4}')
    if [ -w "$f" ]; then
      printf "%b[HIGH]%b WRITABLE set-id binary: %s (%s)\n" "$RED" "$RST" "$f" "$perms"
      printf "       -> overwrite with your own SUID payload\n"
    fi
    if is_gtfo "$b"; then
      printf "%b[HIGH]%b set-id GTFOBins binary: %s (%s)\n" "$RED" "$RST" "$f" "$perms"
      printf "       -> https://gtfobins.github.io/gtfobins/%s/#suid\n" "$b"
    fi
  done
  COUNT=$(printf '%s\n' "$SUID_LIST" | grep -c . 2>/dev/null)
  printf "%b[info]%b %s set-id files scanned\n" "$YEL" "$RST" "$COUNT"
fi

# ---- File capabilities ----------------------------------------------------
printf "\n%b=== File Capabilities ===%b\n" "$CYN" "$RST"
if command -v getcap >/dev/null 2>&1; then
  CAPS=$(getcap -r / 2>/dev/null)
  if [ -n "$CAPS" ]; then
    printf '%s\n' "$CAPS" | while IFS= read -r line; do
      low=$(printf '%s' "$line" | tr 'A-Z' 'a-z')
      hit=""
      for c in $DANGEROUS_CAPS; do
        case "$low" in *"$c"*) hit="$hit $c" ;; esac
      done
      if [ -n "$hit" ]; then
        printf "%b[HIGH]%b %s\n" "$RED" "$RST" "$line"
        printf "       dangerous:%s -> see suid-sudo-capabilities.md\n" "$hit"
      else
        printf "%b[info]%b %s\n" "$YEL" "$RST" "$line"
      fi
    done
  else
    printf "       (none found)\n"
  fi
else
  printf "       getcap not available; try: /sbin/getcap -r / 2>/dev/null\n"
fi

# ---- sudo -l --------------------------------------------------------------
printf "\n%b=== sudo rights ===%b\n" "$CYN" "$RST"
if command -v sudo >/dev/null 2>&1; then
  SVER=$(sudo --version 2>/dev/null | head -1)
  printf "%b[info]%b %s\n" "$YEL" "$RST" "$SVER"
  SUDO_L=$(sudo -n -l 2>/dev/null)
  if [ -n "$SUDO_L" ]; then
    printf '%s\n' "$SUDO_L"
    case "$SUDO_L" in
      *NOPASSWD*|*"(ALL"*) printf "%b[HIGH]%b NOPASSWD / (ALL) rule present\n" "$RED" "$RST" ;;
    esac
    case "$SUDO_L" in
      *LD_PRELOAD*|*LD_LIBRARY_PATH*)
        printf "%b[HIGH]%b env_keep preserves LD_PRELOAD/LD_LIBRARY_PATH -> library hijack\n" "$RED" "$RST"
        printf "       gcc -fPIC -shared -nostartfiles -o /dev/shm/pe.so pe.c; sudo LD_PRELOAD=/dev/shm/pe.so <cmd>\n" ;;
    esac
    # flag GTFOBins binaries in the sudo rules
    for tok in $(printf '%s' "$SUDO_L" | grep -oE '/[A-Za-z0-9_./-]+'); do
      b=$(basename "$tok")
      if is_gtfo "$b"; then
        printf "%b[HIGH]%b sudo-allowed GTFOBins binary: %s\n" "$RED" "$RST" "$b"
        printf "       -> https://gtfobins.github.io/gtfobins/%s/#sudo\n" "$b"
      fi
    done
  else
    printf "       sudo -l requires a password or returned nothing\n"
  fi
else
  printf "       sudo not installed\n"
fi

printf "\n%bDone.%b Cross-reference every HIGH with GTFOBins; pick the lowest-noise escape.\n" "$GREEN" "$RST"
