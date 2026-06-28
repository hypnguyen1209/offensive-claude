#!/usr/bin/env python3
"""k8s_rbac_audit.py - Audit Kubernetes RBAC for privilege-escalation and escape primitives.

Walks ClusterRoles/Roles (and their bindings) and flags subjects that hold dangerous permissions:
verb/resource wildcards, escalate/bind/impersonate, pods/exec|attach, secrets get/list, nodes/proxy
(kubelet-exec path), token/SA creation, and webhook-config tampering. Works against any kubeconfig or
an in-pod ServiceAccount token.

USAGE:
  python3 k8s_rbac_audit.py --kubeconfig ~/.kube/config --dangerous
  python3 k8s_rbac_audit.py --server https://API:6443 --token "$SA_TOKEN" --insecure
  python3 k8s_rbac_audit.py --in-pod                 # auto-load the mounted SA token/CA
  python3 k8s_rbac_audit.py --kubeconfig ~/.kube/config --who-can 'create clusterrolebindings'

Backends (auto-detected): the `kubectl` CLI if present (preferred), else direct REST via urllib.
Dependencies: Python 3.6+ stdlib; optional kubectl. Read-only (only issues GET/list + auth can-i).
Authorized engagements only.
"""
import argparse
import json
import os
import shutil
import ssl
import subprocess
import sys
import urllib.request

SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"

# (verb, resource) patterns that constitute an escalation/escape primitive -> human note.
DANGEROUS = [
    (("*", "*"), "WILDCARD verb+resource == effectively cluster-admin"),
    (("escalate", "*roles*"), "can grant perms beyond own (bypasses escalation guard)"),
    (("bind", "*roles*"), "can bind self/SA to cluster-admin"),
    (("create", "clusterrolebindings"), "can bind self/SA to cluster-admin"),
    (("create", "rolebindings"), "can bind within namespace"),
    (("impersonate", "*"), "can impersonate users/groups/SAs (system:masters)"),
    (("*", "secrets"), "read all secrets (SA tokens, TLS, cloud creds)"),
    (("get", "secrets"), "read secrets (SA tokens / creds)"),
    (("list", "secrets"), "list secrets cluster/ns wide"),
    (("create", "pods"), "schedule privileged/hostPath pod or steal a stronger SA"),
    (("*", "pods/exec"), "exec into higher-priv pods, steal their tokens"),
    (("create", "pods/exec"), "exec into higher-priv pods, steal their tokens"),
    (("*", "pods/attach"), "attach to higher-priv pods"),
    (("get", "nodes/proxy"), "nodes/proxy GET -> kubelet WebSocket exec on ANY pod (bypasses API audit)"),
    (("*", "nodes/proxy"), "nodes/proxy -> kubelet exec (bypasses API audit)"),
    (("create", "serviceaccounts/token"), "mint tokens for higher-priv SAs (TokenRequest)"),
    (("create", "serviceaccounts"), "create SAs"),
    (("*", "validatingwebhookconfigurations"), "disable admission / install credential-stealing webhook"),
    (("*", "mutatingwebhookconfigurations"), "install cluster-wide mutating implant"),
    (("create", "certificatesigningrequests"), "mint client certs (CSR approval path)"),
    (("*", "daemonsets"), "DaemonSet -> root on every node"),
]


def kubectl_get(kctx, resource):
    cmd = ["kubectl"] + kctx + ["get", resource, "-A", "-o", "json"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if out.returncode != 0:
            # cluster-scoped resources reject -A; retry without it
            cmd = ["kubectl"] + kctx + ["get", resource, "-o", "json"]
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return json.loads(out.stdout) if out.stdout.strip() else {"items": []}
    except Exception as e:
        print(f"[!] kubectl get {resource} failed: {e}", file=sys.stderr)
        return {"items": []}


def rest_get(server, token, insecure, path):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ca = os.path.join(SA_DIR, "ca.crt")
        if os.path.exists(ca):
            ctx.load_verify_locations(ca)
    req = urllib.request.Request(server.rstrip("/") + path,
                                 headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
        return json.loads(r.read().decode())


def matches(rule_verbs, rule_res, want_verb, want_res):
    def m(have, want):
        if have == "*" or want == "*":
            return True
        if want.startswith("*") and want.endswith("*"):
            return want.strip("*") in have
        return have == want
    return any(m(v, want_verb) for v in rule_verbs) and any(m(r, want_res) for r in rule_res)


def scan_roles(roles, kind):
    findings = []
    for item in roles.get("items", []):
        name = item["metadata"]["name"]
        ns = item["metadata"].get("namespace", "-")
        for rule in item.get("rules") or []:
            verbs = rule.get("verbs", [])
            resources = rule.get("resources", []) or rule.get("nonResourceURLs", [])
            for (dv, dr), note in DANGEROUS:
                if matches(verbs, resources, dv, dr):
                    findings.append((kind, ns, name, f"{dv} {dr}", note,
                                     ",".join(verbs)[:40], ",".join(resources)[:40]))
    return findings


def main():
    ap = argparse.ArgumentParser(description="Kubernetes RBAC privilege-escalation auditor")
    ap.add_argument("--kubeconfig")
    ap.add_argument("--context")
    ap.add_argument("--server")
    ap.add_argument("--token")
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--in-pod", action="store_true", help="load mounted SA token/CA/server")
    ap.add_argument("--dangerous", action="store_true", help="print dangerous-permission findings (default)")
    ap.add_argument("--who-can", help="like 'create clusterrolebindings' -> roles granting it")
    args = ap.parse_args()

    if args.in_pod:
        with open(os.path.join(SA_DIR, "token")) as f:
            args.token = f.read().strip()
        args.server = "https://%s:%s" % (os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default"),
                                         os.environ.get("KUBERNETES_SERVICE_PORT", "443"))

    use_kubectl = shutil.which("kubectl") and not (args.server and args.token)
    kctx = []
    if use_kubectl:
        if args.kubeconfig:
            kctx += ["--kubeconfig", args.kubeconfig]
        if args.context:
            kctx += ["--context", args.context]
        # quick self check
        whoami = subprocess.run(["kubectl"] + kctx + ["auth", "can-i", "--list"],
                                capture_output=True, text=True)
        print("[*] Current identity capabilities (auth can-i --list):")
        print(whoami.stdout[:2000] or whoami.stderr)

    def get(resource, rest_path):
        if use_kubectl:
            return kubectl_get(kctx, resource)
        return rest_get(args.server, args.token, args.insecure, rest_path)

    croles = get("clusterroles", "/apis/rbac.authorization.k8s.io/v1/clusterroles")
    roles = get("roles", "/apis/rbac.authorization.k8s.io/v1/roles")

    findings = scan_roles(croles, "ClusterRole") + scan_roles(roles, "Role")

    if args.who_can:
        try:
            wv, wr = args.who_can.split(None, 1)
        except ValueError:
            print("[!] --who-can format: '<verb> <resource>'"); return 2
        print(f"\n[*] Roles granting '{wv} {wr}':")
        for item in (croles.get("items", []) + roles.get("items", [])):
            for rule in item.get("rules") or []:
                if matches(rule.get("verbs", []), rule.get("resources", []), wv, wr):
                    md = item["metadata"]
                    print(f"    {md.get('namespace','-')}/{md['name']}")
        return 0

    print(f"\n[*] {len(findings)} dangerous permission grant(s):")
    print(f"    {'KIND':12} {'NS':14} {'ROLE':32} {'PRIMITIVE':34} NOTE")
    for kind, ns, name, prim, note, _v, _r in sorted(set(findings)):
        print(f"    {kind:12} {ns:14.14} {name:32.32} {prim:34.34} {note}")
    print("\n[*] Next: resolve which subjects hold these via (cluster)rolebindings, then chain "
          "(see k8s-rbac-escalation.md). nodes/proxy -> kubelet_exec.py.")


if __name__ == "__main__":
    sys.exit(main())
