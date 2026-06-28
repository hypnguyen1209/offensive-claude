# Ransomware & ESXi / Hypervisor Incident Response

ATT&CK: T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery), T1485 (Data Destruction),
T1489 (Service Stop), T1657 (Financial Theft / extortion), T1078 (Valid Accounts), T1199 (Trusted
Relationship — help-desk). CWE-noinfo.

## Theory / Mechanism

Modern ransomware IR is a **race against an active operator**, not a malware-cleanup exercise. The
goals, in order: (1) **scope & preserve** before anything (image/snapshot, capture the note + a
sample, list affected hosts/datastores), (2) **break the operator's control** (creds, sessions,
hypervisor access, C2), (3) **protect/restore recovery** (backups), (4) eradicate + rebuild.
**Do not** reboot, run the decryptor "to test," or wipe before imaging — you destroy keys-in-memory
and evidence.

Two structural shifts that change the playbook:
- **Hypervisor-level encryption (ESXi/vSphere).** Encrypting at the hypervisor takes down *every* VM
  at once and sits in an **EDR blind spot** (no agent on ESXi/vCenter). The operator SSHes to ESXi,
  `scp`s a ransomware binary into a writable dir (`/tmp`), uses native **`vim-cmd vmsvc/power.off`**
  to force-stop all VMs, then runs the encryptor with `nohup` to survive logout.
- **Backup destruction first (T1490/T1485).** Operators with Domain Admin add themselves to
  **"Veeam Administrators"** (or equivalent), delete backup jobs/snapshots, and clear VSS
  (`vssadmin delete shadows /all`) before encrypting — so check backup integrity immediately.

## Modern 2024-2026 currency (verified)

- **Scattered Spider / UNC3944** (a.k.a. 0ktapus, Octo Tempest, Muddled Libra) — 2025 campaigns pivot
  from pure extortion to full encryption, deploying **DragonForce** on **VMware ESXi**. Initial access
  is **help-desk vishing** (impersonating *employees* to third-party IT, MFA reset/transfer,
  push-bombing, SIM-swap), then **living-off-the-land** AD→vSphere with **extreme velocity**
  (initial access → exfil → encryption in *hours*, not days). High-fidelity IOC: **bulk VM power-off
  commands from a single ESXi host**. They also **join IR bridges / Teams / Slack in real time** —
  assume your incident comms are compromised; coordinate out-of-band.
- **Velociraptor abused for persistence (Talos, Aug 2025, Storm-2603):** outdated **0.73.4.0**
  (**CVE-2025-6264**) installed as stealthy persistence while deploying **LockBit + Babuk + Warlock**;
  relaunched after host isolation; MSI from Azure Blob. ⇒ verify any Velociraptor found (see
  triage-collection ref).
- **Cross-platform builders are the norm:** **LockBit 5.0** (Windows/Linux/ESXi), **Play**
  (separate Windows/ESXi variants), **DragonForce** (Windows/Linux/ESXi/NAS, ≤80% affiliate cut).
- **Defensive shift (GTIG):** move from EDR-centric hunting to **infrastructure-centric** defense —
  phishing-resistant MFA, offline/immutable backups, app-control, "risky login" monitoring, and SIEM
  alerts on mass VM power-off.

## Complete working commands

### Windows host — rapid scope BEFORE eradication
```powershell
# Full automated triage (services, persistence, recent files, ext-change burst, shadow status):
powershell -ep bypass -File scripts/ransomware_triage.ps1 -OutDir C:\IR
# Manual high-signal:
vssadmin list shadows                                  # were shadows deleted? (T1490)
Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102} | Select TimeCreated  # log cleared
Get-ChildItem C:\ -Recurse -Include *.lockbit,*.babuk,*ransom*note* -EA SilentlyContinue
# Identify the encrypted-extension burst window from USN (anchor the timeline):
fsutil usn readjournal C: csv | Select-String 'FILE_CREATE|RENAME' | Select -First 200
```

### ESXi / vCenter — investigate the hypervisor (no EDR here)
```bash
# Is SSH/ESXi Shell enabled (operator turned it on)?  When did logins happen?
vim-cmd hostsvc/get_service_status                      # run on ESXi via DCUI/iLO if SSH is theirs
grep -E 'sshd|SSH login' /var/log/auth.log /var/log/shell.log /var/log/hostd.log
grep -i 'power.off' /var/log/hostd.log                  # bulk VM power-off = the encryption trigger
ls -la /tmp /vmfs/volumes/*/ | grep -iE '\.(sh|out|encrypt)|nohup'   # dropped binaries/scripts
# vCenter: vpxuser anomalies + datastore-wide encrypted-VMDK timestamps
grep -i 'vpxuser' /var/log/vmware/vpxd/vpxd.log
# Collect ESXi host artifacts with UAC (no LiME on ESXi):
./uac -p ir_triage /vmfs/volumes/datastore1/IR
```

### Containment (parallel — break control + protect recovery)
```bash
# Identity (UNC3944 is identity-driven): disable + revoke sessions for compromised accounts
az ad user update --id victim@corp.com --account-enabled false
az rest --method POST --uri "https://graph.microsoft.com/v1.0/users/victim@corp.com/revokeSignInSessions"
# Hypervisor: kill operator SSH access, isolate ESXi mgmt network, snapshot-preserve datastores
vim-cmd hostsvc/stop_ssh                                # if SSH was the operator's channel
# Backups: lock down — verify immutability, pull backup admins added by the actor, take offline copy
# Network: block C2 + isolate; keep one out-of-band channel for IR comms (NOT corp Teams/Slack)
```

### Evidence to keep (chain of custody)
```text
- The ransom note (verbatim) + 2-3 encrypted file samples (+ originals from backup if available)
- Memory image of an infected host (keys may be resident) — see triage-collection/memory-forensics
- USN/$MFT showing the extension-change burst window; cleared-log events (1102/104)
- ESXi hostd/vpxd logs, /tmp drops, SSH/auth logs; vCenter vpxuser activity
- Any Velociraptor binary/config found (version check vs CVE-2025-6264)
```

## Detection

```yaml
title: Mass VM power-off from single ESXi host (pre-encryption, UNC3944)
id: esxi-mass-poweroff-ir
status: experimental
logsource: { product: vmware, service: hostd }
detection:
  sel:
    message|contains: 'power.off'        # or vim-cmd vmsvc/power.off
  timeframe: 5m
  condition: sel | count() by host > 10
level: critical
falsepositives: [planned host maintenance / mass shutdown change window]
```

```yaml
title: Windows mass file rename to ransomware extension
id: ransom-ext-burst-ir
status: experimental
logsource: { product: windows, category: file_event }   # Sysmon 11 / USN
detection:
  sel:
    TargetFilename|endswith: ['.lockbit','.babuk','.dragonforce','.play','.warlock']
  timeframe: 2m
  condition: sel | count() by Image > 50
level: critical
```

IOCs: bulk `vim-cmd power.off` from one host; SSH enabled on ESXi outside change control; `nohup`
encryptor in `/tmp`; new "Veeam Administrators" / backup-admin membership; `vssadmin delete shadows`;
extension-burst in USN; Velociraptor 0.73.4.0; help-desk MFA reset for a privileged user.

## OPSEC

- **Touches:** imaging/snapshotting, disabling accounts, stopping SSH — necessary, but **image
  first**. Don't run the threat actor's decryptor; don't pay-test on production.
- **Cleanup:** after eradication, remove attacker-added backup admins, rotate **all** credentials
  (Kerberos krbtgt twice if DA was compromised), rebuild from known-good, patch the entry vector.
- **Evasion awareness:** the operator may be **watching your IR** (UNC3944 joins bridges) and moving
  in **hours** — coordinate containment on an out-of-band channel and execute identity + hypervisor +
  backup containment **simultaneously** rather than serially, or they'll re-encrypt/wipe ahead of you.

## References

- Google Cloud GTIG "From Help Desk to Hypervisor: Defending vSphere from UNC3944" (2025)
- CISA/FBI/ACSC Scattered Spider advisory (Jul 2025) ; CrowdStrike Services UNC3944 escalation
- Cisco Talos "Velociraptor leveraged in ransomware attacks" (Aug 2025) ; CVE-2025-6264
- Cybersecurity News "Ransomware Attack 2025 Recap" (LockBit 5.0 / Play / DragonForce builders)
