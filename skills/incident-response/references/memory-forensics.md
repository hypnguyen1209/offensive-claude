# Memory Forensics — Volatility 3, Injection & Rootkit (incl. eBPF)

ATT&CK: T1055 (Process Injection), T1003.001 (LSASS Memory), T1014 (Rootkit), T1620 (Reflective
Code Loading), T1027.007 (Dynamic API Resolution). CWE-269 (Improper Privilege Management),
CWE-522 (Insufficiently Protected Credentials).

## Theory / Mechanism

RAM holds what disk cannot: injected/reflectively-loaded code, decrypted payloads, plaintext
credentials & Kerberos tickets, live network connections, and kernel structures a rootkit hides
from userland. **Volatility 3** parses a raw dump using **symbol tables** (ISF JSON) instead of
v2 profiles — it auto-detects the OS/kernel and maps kernel/process structures to names. Linux/macOS
need a matching symbol pack (build with `dwarf2json` from the target kernel's debug symbols / `vmlinux`).

Core hunting ideas:
- **Process integrity:** cross-reference `pslist` (walks the active `EPROCESS` list) vs `psscan`
  (pool-tag carving). A process in `psscan` but not `pslist` = DKOM unlinking (hidden process).
  Inspect parent→child (reparented `svchost`, `cmd` spawned by Office) and typosquats (`svch0st`).
- **Injection:** `malfind` flags private, committed, **executable** VAD regions not backed by an
  image file (classic shellcode / reflective DLL). `hollowprocesses` finds image-section mismatch
  (process hollowing). RWX/RX private pages + a PE header `MZ` in private memory = injected module.
- **Credentials:** dump `lsass` and run mimikatz/pypykatz offline, or use built-in hive plugins.
- **Rootkits:** SSDT/IDT/IRP hooks, callback removal, hidden kernel modules, and — on modern Linux —
  **eBPF programs** that hook syscalls and even hide themselves from `bpftool`.

## Modern 2024-2026 currency (verified)

- **Volatility 3 is the standard** (Python 3, symbol tables, Windows/Linux/macOS). New Linux plugins
  added through Framework 2.x: `linux.ebpf`, `linux.hidden_modules`, `linux.kthreads`,
  `linux.pagecache`, `linux.pidhashtable`, `linux.ptrace`, `linux.boottime`.
- **eBPF rootkits are a 2024-2026 blind spot.** PoCs (TripleCross, ebpfkit, boopkit, pamspy) and a
  real in-the-wild implant **LinkPro** (Synacktiv, Oct 2025) hook syscalls via eBPF. LinkPro, found
  in a compromised **AWS/EKS** environment (initial access via **Jenkins CVE-2024-23897**), loads two
  eBPF modules:
  - **"Hide"** — `tracepoint`/`kretprobe` on `getdents`/`getdents64` (file hiding for names like
    `.tmp~data`/`.system`), hides up to 10 PIDs from `/proc`, and hooks `sys_bpf` to make its *own*
    BPF programs invisible to `bpftool` using **`bpf_override_return`** (needs the kernel built with
    `CONFIG_BPF_KPROBE_OVERRIDE` — true on recent Amazon Linux / Ubuntu 24.04).
  - **"Knock"** — XDP `xdp_ingress` watches for a magic TCP SYN with **window size 54321**, then
    redirects that source IP's packets to internal port **2233**; `tc_egress` rewrites the response
    so firewall logs don't correlate.
  - Persistence as fake `systemd-resolveld.service`; binary at
    `/usr/lib/.system/.tmp~data.resolveld`; userland fallback via `/etc/ld.so.preload` → `libld.so`
    filtering `/proc/net/*` lines containing `:2233`. **Detection gap the authors left:** map/link FDs
    are *not* hidden, so listing eBPF maps/links still reveals the implant + its PID.
- **Detection truth:** `bpftool prog list`, `ss`, `ps` all run **on the compromised kernel** and can
  be lied to. Acquire RAM **out-of-band** (hypervisor snapshot / cloud memory API / LiME from RO
  media) and analyse offline. `bpf_override_return` in a loaded program is a strong IOC.

## Complete working commands

### Windows triage (Volatility 3)
```bash
# Identify & process triage
vol3 -f mem.raw windows.info
vol3 -f mem.raw windows.pslist
vol3 -f mem.raw windows.psscan            # carve — compare to pslist for hidden procs
vol3 -f mem.raw windows.pstree            # parent/child anomalies
vol3 -f mem.raw windows.cmdline
vol3 -f mem.raw windows.netscan           # connections (carved) ; windows.netstat (list)

# Injection / hollowing / reflective loading
vol3 -f mem.raw windows.malfind --dump    # dumps injected regions to ./
vol3 -f mem.raw windows.hollowprocesses
vol3 -f mem.raw windows.vadinfo --pid <PID> | grep -i 'PAGE_EXECUTE_READWRITE'
vol3 -f mem.raw windows.ldrmodules --pid <PID>   # unlinked/hidden DLLs (3-list compare)

# Credentials & persistence
vol3 -f mem.raw windows.lsadump
vol3 -f mem.raw windows.hashdump
vol3 -f mem.raw windows.registry.printkey --key 'Software\Microsoft\Windows\CurrentVersion\Run'
# LSASS dump for offline pypykatz:
vol3 -f mem.raw windows.dumpfiles --pid <lsass_pid>
pypykatz lsa minidump lsass.dmp

# Kernel rootkit
vol3 -f mem.raw windows.ssdt | grep -vi ntoskrnl   # hooks resolving outside ntoskrnl/win32k
vol3 -f mem.raw windows.callbacks
vol3 -f mem.raw windows.driverirp
vol3 -f mem.raw windows.modscan          # carved drivers; diff vs windows.modules
```

### Linux triage (Volatility 3) — needs symbol pack
```bash
# Build symbols if not auto-resolved (run on a box with the target kernel's vmlinux/dwarf):
dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-$(uname -r) > kernel.json
# Place kernel.json under volatility3/symbols/linux/ then:
vol3 -f mem.lime linux.pslist
vol3 -f mem.lime linux.pstree
vol3 -f mem.lime linux.bash               # recovered shell history (incl. cleared ~/.bash_history)
vol3 -f mem.lime linux.lsof
vol3 -f mem.lime linux.sockstat
# Rootkit detection
vol3 -f mem.lime linux.check_syscall      # syscall table hooks
vol3 -f mem.lime linux.check_modules      # module list vs sysfs
vol3 -f mem.lime linux.hidden_modules     # carve unlinked modules
vol3 -f mem.lime linux.tracing.ftrace     # ftrace-based hooks
# eBPF (LinkPro-class implants):
vol3 -f mem.lime linux.ebpf               # enumerate loaded BPF progs even if bpftool is blinded
```

### eBPF rootkit hunt on a live/IR Linux host
```bash
bash scripts/ebpf_rootkit_hunt.sh         # see scripts/ — full LinkPro-aware checks
# Manual high-signal checks:
sudo bpftool prog show                    # may be lied to; compare to a baseline / memory
sudo bpftool prog dump xlated id <ID> | grep -i bpf_override_return   # strong IOC
ss -tanp | sort > /tmp/ss.txt             # netlink — bypasses /proc/net libld.so hook
grep -v -E ':(2233|54321) ' /proc/net/tcp > /dev/null  # port 2233 / win 54321 LinkPro IOCs
cat /etc/ld.so.preload 2>/dev/null        # unexpected entry == userland-fallback hooking
ls -la /usr/lib/.system/ 2>/dev/null      # LinkPro staging dir
systemctl cat systemd-resolveld.service 2>/dev/null   # NOTE the typosquat vs systemd-resolved
```

## Detection

```yaml
title: eBPF program using bpf_override_return (kernel-hiding rootkit)
id: 3f1c2a90-ebpf-override-ir
status: experimental
logsource:
  category: bpf
  product: linux
detection:
  sel:
    bpf_helper: 'bpf_override_return'     # from bpf audit / sysmon-for-linux BPF events
  prog_type:
    - 'kprobe'
    - 'tracepoint'
  condition: sel and prog_type
level: high
falsepositives:
  - Error-injection testing harnesses (rare in production)
```

EDR/host telemetry: `bpf()` syscalls loading `tracepoint/getdents*` or `xdp`/`tc` programs from
unexpected processes; writes to `/etc/ld.so.preload`; new units named like `systemd-resolveld`;
`ss`(netlink) listeners that don't appear in `netstat`(/proc). Windows: malfind RWX private regions,
LSASS handle opens with suspicious access masks, unsigned drivers from modscan.

Synacktiv YARA: `MAL_LinkPro_ELF_Rootkit_Golang_Oct25`, `MAL_LinkPro_Hide_ELF_BPF_Oct25`.

## OPSEC

- **Touches:** read-only on the dump file. The *only* mutation risk is acquiring RAM (see
  triage-collection). Work on a copy; keep the original hashed and read-only.
- **Cleanup:** none for analysis. Delete dumped processes/DLLs from your workstation when the case
  closes (they may contain credentials/PII).
- **Evasion awareness:** never trust on-host `bpftool`/`ps`/`ss`/`lsmod` against a kernel rootkit.
  For eBPF specifically, the implant may hide its programs but leak maps/links — enumerate **both**.
  Compare against a known-good baseline of the same kernel build.

## References

- Synacktiv "LinkPro: eBPF rootkit analysis" (Oct 2025) — synacktiv.com/en/publications/linkpro-ebpf-rootkit-analysis
- Andrea Fortuna "eBPF rootkits and the Volatility blind spot" (2026)
- "BPF Memory Forensics with Volatility 3" — lolcads.github.io (7-plugin BPF suite)
- DFRWS 2025 "Detecting hidden kernel modules in memory snapshots"
- Volatility 3 framework + symbols — github.com/volatilityfoundation/volatility3 ; dwarf2json
- Jenkins CVE-2024-23897 (LinkPro initial access)
