#!/usr/bin/env python3
"""
gcp_impersonation_mapper.py - Build the GCP service-account impersonation graph for a project:
who can impersonate whom (roles/iam.serviceAccountTokenCreator, .actAs, key creation), and which
chains reach a high-privilege identity (owner/editor/security/iam admin).

The danger in GCP is rarely a single binding; it is a CHAIN (A -> B -> C -> org admin) where each
edge looks benign. This tool enumerates the edges and reports reachable privileged targets.

USAGE
  python3 gcp_impersonation_mapper.py --project TARGET [--out gcp_graph.json]
  python3 gcp_impersonation_mapper.py --project TARGET --start you@example.com

WHAT IT CHECKS (read-only)
  - Project IAM policy (principals -> roles).
  - Per-SA IAM policy: who holds tokenCreator / actAs / serviceAccountKeyAdmin on each SA.
  - Builds a directed graph and does BFS from --start (default: active gcloud account) to any SA
    that holds a privileged project role.

DEPENDENCIES
  pip install google-cloud-iam google-cloud-resource-manager google-auth
  OR rely on `gcloud` being installed (the tool falls back to `gcloud ... --format=json`).
  Auth: Application Default Credentials or an active gcloud session.

OPSEC
  getIamPolicy calls are Admin Activity / Data Access logged. Read-only; performs no impersonation.
"""
import argparse
import collections
import json
import shutil
import subprocess
import sys

PRIV_ROLES = {
    "roles/owner", "roles/editor",
    "roles/iam.securityAdmin", "roles/iam.serviceAccountAdmin",
    "roles/iam.serviceAccountKeyAdmin", "roles/iam.organizationRoleAdmin",
    "roles/resourcemanager.organizationAdmin", "roles/resourcemanager.projectIamAdmin",
}
IMPERSONATE_ROLES = {
    "roles/iam.serviceAccountTokenCreator",   # mint tokens for the target SA
    "roles/iam.serviceAccountUser",           # actAs (attach to created resources)
    "roles/iam.serviceAccountKeyAdmin",       # mint long-lived keys for the target SA
    "roles/iam.workloadIdentityUser",         # federated impersonation
}


def gcloud_json(args):
    """Run a gcloud command returning JSON; exit on failure."""
    if not shutil.which("gcloud"):
        sys.exit("[!] gcloud not found and SDK fallback unavailable; install gcloud or the SDKs.")
    cmd = ["gcloud"] + args + ["--format=json"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=120)
    except subprocess.CalledProcessError as e:
        sys.exit(f"[!] {' '.join(cmd)} failed:\n{e.stderr}")
    return json.loads(out.stdout or "[]")


def active_account():
    accts = gcloud_json(["auth", "list", "--filter=status:ACTIVE"])
    return accts[0]["account"] if accts else None


def list_service_accounts(project):
    sas = gcloud_json(["iam", "service-accounts", "list", "--project", project])
    return [s["email"] for s in sas]


def project_iam(project):
    pol = gcloud_json(["projects", "get-iam-policy", project])
    # member -> set(roles)
    out = collections.defaultdict(set)
    for b in pol.get("bindings", []):
        for m in b.get("members", []):
            out[m].add(b["role"])
    return out


def sa_iam(project, sa_email):
    pol = gcloud_json(
        ["iam", "service-accounts", "get-iam-policy", sa_email, "--project", project]
    )
    out = collections.defaultdict(set)
    for b in pol.get("bindings", []):
        for m in b.get("members", []):
            out[m].add(b["role"])
    return out


def norm(member):
    """Strip member type prefix -> bare identity (user:/serviceAccount:/group:)."""
    return member.split(":", 1)[1] if ":" in member else member


def main():
    p = argparse.ArgumentParser(description="GCP SA impersonation graph mapper")
    p.add_argument("--project", required=True)
    p.add_argument("--start", help="starting principal (default: active gcloud account)")
    p.add_argument("--out", help="write full graph JSON")
    a = p.parse_args()

    start = a.start or active_account()
    if not start:
        sys.exit("[!] no active account; pass --start <principal>")
    print(f"[*] Project: {a.project}")
    print(f"[*] Start  : {start}\n")

    proj_roles = project_iam(a.project)
    sas = list_service_accounts(a.project)
    print(f"[*] {len(sas)} service account(s) found; mapping impersonation edges ...")

    # Build directed edges: principal --(can impersonate)--> sa
    edges = collections.defaultdict(set)        # principal -> set(target_sa)
    edge_reason = {}                            # (principal, sa) -> roles
    privileged_sas = set()
    for sa in sas:
        if PRIV_ROLES & proj_roles.get(f"serviceAccount:{sa}", set()):
            privileged_sas.add(sa)
        for member, roles in sa_iam(a.project, sa).items():
            imp = roles & IMPERSONATE_ROLES
            if imp:
                principal = norm(member)
                edges[principal].add(sa)
                edge_reason[(principal, sa)] = sorted(imp)

    if privileged_sas:
        print(f"[*] Privileged SAs (hold {'/'.join(sorted(PRIV_ROLES))[:40]}...): "
              f"{len(privileged_sas)}")

    # BFS from start across impersonation edges to any privileged SA
    seen = {start}
    queue = collections.deque([(start, [start])])
    hits = []
    while queue:
        node, path = queue.popleft()
        for tgt in edges.get(node, ()):
            if tgt in seen:
                continue
            seen.add(tgt)
            newpath = path + [tgt]
            if tgt in privileged_sas or (PRIV_ROLES & proj_roles.get(f"serviceAccount:{tgt}", set())):
                hits.append(newpath)
            queue.append((tgt, newpath))

    if hits:
        print(f"\n[+] {len(hits)} impersonation chain(s) reaching a privileged SA:\n")
        for path in hits:
            print("  " + "  ->  ".join(path))
            for i in range(len(path) - 1):
                why = edge_reason.get((path[i], path[i + 1]), [])
                print(f"        [{path[i]} -> {path[i+1]}] via {', '.join(why)}")
            print()
    else:
        print("\n[-] No impersonation chain from start reaches a privileged SA "
              "(check direct project roles separately).")

    print("[*] Direct roles on start principal:")
    for r in sorted(proj_roles.get(f"user:{start}", set()) | proj_roles.get(f"serviceAccount:{start}", set())):
        print(f"      {r}")

    if a.out:
        graph = {
            "project": a.project,
            "start": start,
            "edges": {k: sorted(v) for k, v in edges.items()},
            "edge_reasons": {f"{k[0]}|{k[1]}": v for k, v in edge_reason.items()},
            "privileged_sas": sorted(privileged_sas),
            "chains_to_privileged": hits,
        }
        with open(a.out, "w") as fh:
            json.dump(graph, fh, indent=2)
        print(f"\n[*] Graph -> {a.out}")


if __name__ == "__main__":
    main()
