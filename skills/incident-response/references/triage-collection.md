# Triage & Evidence Collection

ATT&CK: T1074 (Data Staged — here, *defensive* staging of evidence), T1219 (Remote Access
Software — relevant to verifying abused DFIR tooling). CWE-778 (Insufficient Logging),
CWE-269 (Improper Privilege Management — Velociraptor CVE-2025-6264).

## Theory / Mechanism

The first job of an incident responder is to **capture volatile state before it disappears and
without contaminating it**. Two principles govern everything:

1. **Order of Volatility (RFC 3227):** CPU registers/cache → RAM → network state & running
   processes → disk → remote logs/archival media. Acquire from most→least volatile. In practice:
   **RAM first, then a triage collection, then a full disk image if warranted.** Never reboot or
   "just shut it down" a live suspect host — you destroy memory-resident malware, injected code,
   decryption keys, and network state.
2. **Forensic soundness:** write evidence to a *separate* device, hash on acquisition
   (SHA-256), maintain chain of custody, work on copies. On endpoints prefer agents/collectors
   that minimise writes to the suspect volume (which scrambles `$UsnJrnl`, MFT, Prefetch).

Two collection postures:
- **Live response / triage** — a fast, scoped artifact grab from a running host (logs, registry,
  $MFT, prefetch, browser, process/network state). Hours of value in minutes; used to scope before
  deciding which hosts deserve a full image.
- **Full forensic image** — bit-for-bit disk + RAM for deep/legal cases.

## Modern 2024-2026 currency (verified)

- **Velociraptor 0.75 (Aug 2025)** — leading open-source endpoint DFIR. Reworked Sigma editor, new
  Linux/Windows live event sources, multi-select hunt management, artifact tagging
  (`artifact_set_metadata`), and `Server.Import.ArtifactExchange` to bulk-import the Exchange. The
  **offline collector** bakes a config + chosen artifacts (and any 3rd-party tools) into a single
  self-contained binary — ideal when a network is severed and a local admin (non-DFIR) must run it.
  Note **CVE-2026-6948** (unbounded memory allocation in the VQLResponse result-set writer) — run a
  patched build of your own server.
- **Velociraptor abused as adversary persistence — CVE-2025-6264 (Aug 2025, Talos / Storm-2603):**
  ransomware actors installed an **outdated Velociraptor 0.73.4.0** to maintain stealthy persistence
  while deploying LockBit/Babuk/Warlock. The flaw: `Admin.Client.UpdateClientConfig` did not enforce
  an extra permission, so `COLLECT_CLIENT` (Investigator role) → arbitrary command execution /
  endpoint takeover. Patched in **0.73.5**. MSI installers were hosted on **Azure Blob storage**;
  Velociraptor **relaunched even after host isolation**. ⇒ During triage, treat *any unexpected
  Velociraptor* as a possible C2/persistence implant — verify version ≥0.73.5 and that the service
  matches your own deployment.
- **UAC (Unix-like Artifacts Collector, tclahr) — current** — single dependency-free shell script
  for AIX, ESXi, FreeBSD, Linux, macOS, NetBSD, NetScaler, OpenBSD, Solaris. Profiles: `full`,
  `ir_triage`, `offline`, `offline_ir_triage`. YAML-defined artifacts, respects order of volatility,
  collects from processes with no on-disk binary, builds a bodyfile for timelining. `--enable-modifiers`
  permits state-changing artifacts (off by default).
- **LinuxCatScale (WithSecure)** — bash LotL collector for Linux with a bundled ELK ingest. Run from
  external/USB media with sudo to avoid overwriting evidence.
- **KAPE (Kroll)** — Windows targets+modules collector; `!SANS_Triage` target is the standard fast
  triage set; chain to EZ-tool modules for parsing.
- **Dissect / Acquire (Fox-IT)** and the **Velociraptor Offline Collector** both produce portable
  "forensic packages" for Windows/Linux/macOS that drop straight into Timesketch.

## Complete working commands

### RAM acquisition (do this first)
```bash
# Windows (WinPMEM / latest velociraptor builds embed it):
winpmem_mini_x64_rc2.exe E:\evidence\HOST_mem.raw         # writes raw; or .aff4
# Microsoft AVML (Linux, no kernel module, static binary) — preferred on cloud Linux:
sudo ./avml /evidence/host_mem.lime
# LiME (Linux Memory Extractor) when you must build a module matching the kernel:
sudo insmod lime-$(uname -r).ko "path=/evidence/host_mem.lime format=lime"
# ESXi: no LiME; snapshot the VM at hypervisor level or use vm-support; for the ESXi host
#       itself collect with UAC (-p ir_triage) over SSH.
```

### Velociraptor — build & run an offline collector (severed-network friendly)
```bash
# Build a self-contained Windows triage collector from your server config (no recompile):
velociraptor --config server.config.yaml collector \
  --target ZIP --output WinTriage.exe \
  artifacts add Windows.KapeFiles.Targets --args Device=C: --args _SANS_Triage=Y \
  artifacts add Windows.Memory.Acquisition
# Run on the endpoint (writes Collection-<host>-<ts>.zip locally; can auto-upload to S3/Azure):
WinTriage.exe
# Network-wide hunt on a live deployment (Sigma editor reworked in 0.75):
velociraptor --config server.config.yaml query \
  'SELECT * FROM hunt(description="IR triage", artifacts=["Windows.KapeFiles.Targets",
   "Windows.Memory.Acquisition"], args=dict(Device="C:"))'
```

### KAPE (Windows) — fast triage to a clean evidence drive
```cmd
kape.exe --tsource C: --tdest E:\triage\%m --target !SANS_Triage --vhdx HOST ^
         --zip HOST --gui
:: parse collected artifacts with EZ-tool modules in one pass:
kape.exe --msource E:\triage\%m --mdest E:\parsed\%m --module !EZParser --mflush
```

### UAC / CatScale (Linux / Unix / ESXi)
```bash
# UAC IR triage profile (+ custom artifacts), write to mounted evidence volume:
./uac -p ir_triage -a /opt/custom_artifacts/* /mnt/evidence
./uac --artifacts list linux          # show what would run on this OS
# UAC for ESXi host (over SSH, busybox-safe):
./uac -p ir_triage /vmfs/volumes/datastore1/IR
# CatScale (run from USB with sudo, auto-compresses + can feed ELK):
chmod +x Cat-Scale.sh && sudo ./Cat-Scale.sh
```

### Disk imaging (when triage warrants full image)
```bash
# Forensic, verified, compressed; ewfacquire writes E01 with hashes baked in:
sudo ewfacquire -t /evidence/HOST -f encase6 -c best -d sha256 /dev/sda
# Quick raw with progress + on-the-fly hash:
sudo dc3dd if=/dev/sda hof=/evidence/HOST.img hash=sha256 log=/evidence/HOST.dc3dd.log
```

### Verify suspect DFIR tooling (Velociraptor persistence check)
```bash
# Windows: is there an unexpected/old Velociraptor service? (<0.73.5 == CVE-2025-6264 exposure)
sc query velociraptor 2>NUL
wmic service where "PathName like '%velociraptor%'" get Name,PathName,StartMode
"C:\Program Files\Velociraptor\velociraptor.exe" version   # compare to 0.73.5+ baseline
# Look for the abuse IOCs: MSI from Azure Blob, relaunch after isolation, config you didn't deploy.
python3 scripts/triage_collector.py --check-velociraptor    # automated check, see scripts/
```

## Detection

Evidence collection itself generates telemetry; bake expected DFIR tooling into your baseline so it
doesn't drown real signal, and alert on *unexpected* collectors (the Velociraptor-abuse case).

```yaml
title: Unexpected Velociraptor Service Install (possible CVE-2025-6264 persistence)
id: 0b6c8b6d-9a2e-4f31-8d3a-velociraptor-ir
status: experimental
logsource:
  product: windows
  service: system          # or sysmon
detection:
  svc_install:
    EventID: 7045          # Service installed
    ImagePath|contains: 'velociraptor'
  msi_blob:
    EventID: 7045
    ImagePath|contains:
      - '.blob.core.windows.net'
  condition: svc_install or msi_blob
fields: [ImagePath, ServiceName, AccountName]
level: high
falsepositives:
  - Your own authorized Velociraptor deployment (allowlist its hash/path/version >=0.73.5)
```

IOCs to record per triage: collector hashes, evidence-drive serial, acquisition operator + UTC time,
acquisition tool versions. For the Velociraptor-abuse cluster: `velociraptor.exe` version `0.73.4.0`,
MSI delivered from `*.blob.core.windows.net`, service that relaunches post-isolation.

## OPSEC

- **Touches:** mounting evidence media, loading a kernel module (LiME) or driver (winpmem),
  creating a service/scheduled task for an agent collector, and (unavoidably) some writes to the
  source `$UsnJrnl`/registry on a *live* host. Minimise by writing output off-host.
- **Cleanup:** remove temporary collector services/drivers after acquisition; `rmmod lime`.
  Document anything you changed (you altered the scene — note it for court).
- **Evasion awareness:** memory-resident or eBPF rootkits will lie to on-host tools — for those,
  acquire RAM out-of-band (hypervisor snapshot, cloud memory-dump API, or LiME from RO media before
  any in-scope process starts). Sophisticated actors (UNC3944) monitor internal comms and may watch
  for collector deployment — coordinate on out-of-band channels.

## References

- Velociraptor 0.75 release notes — docs.velociraptor.app/blog/2025/2025-08-30-release-notes-0.75/
- Offline collectors — docs.velociraptor.app/docs/deployment/offline_collections/
- CVE-2025-6264 advisory — docs.velociraptor.app/announcements/advisories/cve-2025-6264/ ;
  GHSA-gpfc-mph4-qm24 ; Talos "Velociraptor leveraged in ransomware attacks" (Aug 2025)
- UAC — github.com/tclahr/uac ; LinuxCatScale — github.com/WithSecureLabs/LinuxCatScale
- Microsoft AVML — github.com/microsoft/avml ; KAPE — Kroll
- RFC 3227 — Guidelines for Evidence Collection and Archiving
