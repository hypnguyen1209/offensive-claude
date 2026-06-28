#!/usr/bin/env python3
"""
k8s_can_i_abuse.py - Map the abuse primitives available to the current Kubernetes
ServiceAccount / kubeconfig context: which RBAC verbs enable privilege escalation,
secret theft, node breakout, or token minting.

USAGE
  # Using a kubeconfig:
  python3 k8s_can_i_abuse.py --kubeconfig ./kubeconfig
  # In-pod (uses the mounted ServiceAccount token + in-cluster API):
  python3 k8s_can_i_abuse.py --in-pod
  # Explicit token/server:
  python3 k8s_can_i_abuse.py --server https://API:6443 --token "$TOKEN" [--insecure]

WHAT IT DOES
  Runs SelfSubjectAccessReview (the API behind `kubectl auth can-i`) for a curated set of
  high-impact (verb,resource) pairs and prints which abuse PRIMITIVES are available, with the
  next exploitation step for each.

DEPENDENCIES
  pip install requests   (talks to the API directly; no kubernetes client required)
  Falls back to `kubectl auth can-i` if --use-kubectl is given.

OPSEC
  SelfSubjectAccessReview is allowed for all authenticated users and is low-signal, but the
  requests still hit the kube audit log. Performs no mutating actions.
"""
import argparse
import base64
import json
import os
import shutil
import ssl
import subprocess
import sys
import urllib.request

# (verb, resource, subresource, namespace-scope) -> (primitive name, exploitation note)
CHECKS = [
    (("create", "pods", "", True), ("Run privileged/hostPath pod", "schedule pod mounting hostPath / -> node FS (T1610/T1611)")),
    (("create", "pods/exec", "", True), ("Exec into other pods", "exec into a higher-priv pod, steal its SA token (T1078)")),
    (("create", "pods/attach", "", True), ("Attach to pods", "attach to a privileged pod for shell/IO")),
    (("get", "secrets", "", True), ("Read secrets", "dump SA tokens / app secrets in scope")),
    (("list", "secrets", "", True), ("List/read all secrets", "enumerate every secret in namespace/cluster")),
    (("create", "serviceaccounts/token", "", True), ("Mint SA tokens (TokenRequest)", "mint tokens for privileged SAs")),
    (("create", "clusterrolebindings", "", False), ("Create ClusterRoleBinding", "bind self to cluster-admin")),
    (("create", "rolebindings", "", True), ("Create RoleBinding", "bind self to a privileged Role")),
    (("escalate", "clusterroles", "", False), ("escalate verb on clusterroles", "grant self perms beyond your ceiling -> cluster-admin")),
    (("bind", "clusterroles", "", False), ("bind verb on clusterroles", "bind any clusterrole (incl. cluster-admin)")),
    (("impersonate", "users", "", False), ("Impersonate users", "act as system:admin via --as")),
    (("impersonate", "serviceaccounts", "", True), ("Impersonate ServiceAccounts", "act as a privileged SA")),
    (("get", "nodes/proxy", "", False), ("nodes/proxy", "reach kubelet API on every node -> exec in any pod")),
    (("create", "pods/portforward", "", True), ("Port-forward pods", "reach internal services / pivot")),
    (("*", "*", "", False), ("Wildcard (cluster-admin)", "full cluster control")),
    (("update", "daemonsets", "", True), ("Update DaemonSets", "schedule a malicious pod on every node")),
    (("patch", "nodes", "", False), ("Patch nodes", "label/taint manipulation, scheduling control")),
]


def kubectl_can_i(verb, resource, sub, kubeconfig):
    res = f"{resource}/{sub}" if sub else resource
    cmd = ["kubectl", "auth", "can-i", verb, res]
    if kubeconfig:
        cmd += ["--kubeconfig", kubeconfig]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        return out.stdout.strip().lower().startswith("yes")
    except Exception:
        return False


class APIClient:
    def __init__(self, server, token, insecure):
        self.server = server.rstrip("/")
        self.token = token
        self.ctx = ssl.create_default_context()
        if insecure:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def ssar(self, verb, resource, sub, namespace):
        attrs = {"verb": verb, "resource": resource, "namespace": namespace or "default"}
        if sub:
            attrs["subresource"] = sub
        body = json.dumps({
            "kind": "SelfSubjectAccessReview",
            "apiVersion": "authorization.k8s.io/v1",
            "spec": {"resourceAttributes": attrs},
        }).encode()
        url = f"{self.server}/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Authorization", f"Bearer {self.token}")
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=15) as r:
                resp = json.loads(r.read())
            return resp.get("status", {}).get("allowed", False)
        except Exception as e:
            return f"err:{e}"


def in_pod_defaults():
    base = "/var/run/secrets/kubernetes.io/serviceaccount"
    token = open(os.path.join(base, "token")).read().strip()
    host = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
    port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    return f"https://{host}:{port}", token


def main():
    p = argparse.ArgumentParser(description="Kubernetes RBAC abuse-primitive mapper")
    p.add_argument("--kubeconfig")
    p.add_argument("--server")
    p.add_argument("--token")
    p.add_argument("--in-pod", action="store_true")
    p.add_argument("--insecure", action="store_true")
    p.add_argument("--use-kubectl", action="store_true", help="shell out to kubectl auth can-i")
    a = p.parse_args()

    use_kubectl = a.use_kubectl or (a.kubeconfig and not a.token and not shutil.which("python3"))
    client = None
    if not use_kubectl:
        if a.in_pod:
            server, token = in_pod_defaults()
            client = APIClient(server, token, True)
        elif a.server and a.token:
            client = APIClient(a.server, a.token, a.insecure)
        elif a.kubeconfig and shutil.which("kubectl"):
            use_kubectl = True   # simplest path for a kubeconfig
        else:
            sys.exit("[!] provide --in-pod, --server+--token, or --kubeconfig (with kubectl).")

    print("[*] Checking abuse primitives via SelfSubjectAccessReview ...\n")
    available = []
    for (verb, resource, sub, ns), (name, note) in CHECKS:
        if use_kubectl:
            allowed = kubectl_can_i(verb, resource, sub, a.kubeconfig)
        else:
            allowed = client.ssar(verb, resource, sub, "default")
        if allowed is True:
            available.append((name, verb, resource, sub, note))
            res = f"{resource}/{sub}" if sub else resource
            print(f"  [ABUSE] {name:<34} ({verb} {res})")
            print(f"          -> {note}")

    if not available:
        print("[-] No high-impact primitives available to this identity.")
    else:
        print(f"\n[+] {len(available)} abuse primitive(s) available. "
              "See references/kubernetes-container-escape.md for exploitation.")


if __name__ == "__main__":
    main()
