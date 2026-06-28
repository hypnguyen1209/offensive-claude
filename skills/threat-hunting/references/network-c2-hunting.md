# Network & C2 Hunting — JA4+, Beaconing, DNS Tunneling, Framework Signatures

## Theory / Mechanism

As traffic moves to TLS 1.3 + encrypted SNI/ECH, payload inspection dies and hunters pivot
to **metadata**: who talks to whom, how often, how regularly, how big, and *how the client
negotiates*. Two orthogonal signals catch C2:

1. **Fingerprinting** (`JA4+`) — *who/what* the client/server is, regardless of decryption.
2. **Behavioral statistics** (beaconing, long connections, prevalence) — *how* it talks.

Use both. A multi-fingerprint + behavioral approach narrows the gap between FP and TP.

## JA4+ fingerprinting (T1071.001, CWE-300)

**JA4+** (FoxIO, launched Sep 2023; adopted by Cloudflare, AWS, VirusTotal, NetWitness) is
the JA3 successor. JA3's fatal flaw: it hashed TLS extensions *in order*, so Chromium's
2023 extension-order randomization (and "cipher stunting") broke it. **JA4 sorts
extensions and ciphers by type**, so it is stable against randomization and adds ALPN.

The suite is multi-protocol/multi-layer:

| Fingerprint | Layer | Hunting use |
|-------------|-------|-------------|
| **JA4**  | TLS client hello | Identify client app/library; mismatch = mimicry |
| **JA4S** | TLS server hello | Identify C2 server stack |
| **JA4H** | HTTP client (method, headers, order) | App-level signature; missing `Accept-Language` = bot |
| **JA4X** | X.509 cert *generation* | Catch frameworks that randomize cert contents |
| **JA4L** | Latency/locality | Geolocate true endpoint behind proxy |

**JA4 is segmented (`a_b_c`)** — pivot on a *single* segment. Classic hunt: a host makes
outbound TLS where segments `a` and `c` match Chrome but segment `b` (cipher/extension set)
deviates — a tool mimicking a browser. Pivot on `b` across the fleet to surface the whole
beacon population hidden in "browser-like" traffic.

**JA4X is the killer for modern C2.** Sliver dedicates 400+ lines to *randomly generating*
TLS certs, so each cert hash is unique and useless to pivot on — but every cert is generated
by the *same code*, so they share a **JA4X**. **Havoc** reuses most Sliver code and shares
that JA4X (differentiate by Org Name / Postal Code length). JA4X detects SoftEther, Tor,
Metasploit, Sliver, Havoc, and many RATs. Caveat: certs are cleartext in TLS 1.2 but
*encrypted* in TLS 1.3, so JA4X works at the proxy/NDR/firewall layer that terminates or
inspects TLS.

```bash
# Generate JA4+ from a PCAP with FoxIO's tool (ja4+ suite)
git clone https://github.com/FoxIO-LLC/ja4 && cd ja4
# Wireshark/tshark plugin or the standalone ja4 binary:
./ja4 -f capture.pcap                 # emits JA4, JA4S, JA4H, JA4X per flow
tshark -r capture.pcap -T fields -e ja4.ja4 -e ip.dst -e tls.handshake.extensions_server_name
```

```python
# Zeek script idea: log JA4 and alert on known-bad fingerprints (zeek-ja4 package)
# (deploy via: zkg install zeek/foxio/ja4)
# In local.zeek:
#   @load ja4
#   redef JA4PLUS::known_bad_ja4 += { "t13d1516h2_8daaf6152771_b186095e22b6" };  # example Sliver-like
```

A curated list of bad JA4/JA4S/JA4X (Sliver, Havoc, Metasploit, CS) is the input to
`scripts/beacon_hunter.py --ja4-blocklist`.

## Beaconing detection (T1071, T1571, CWE-940)

C2 beacons phone home on a fixed interval (+ jitter) with consistent payload sizes. Human
traffic is bursty and irregular; beacons are periodic and uniform. The statistical test:

> For connections from host→dest, compute inter-arrival deltas. If
> `stddev(delta) / mean(delta) < ~0.3` **and** payload sizes are tightly clustered →
> likely beacon. Add **prevalence**: if only *one* internal host talks to that external
> dest, suspicion rises. **Long connections** (minutes-hours) on non-SSH/RDP/VNC protocols
> are also C2-indicative.

**RITA** (Active Countermeasures; now maintained by SsoT AG) operationalizes exactly this
over **Zeek** logs — beaconing, long-connection, DNS-tunneling, and threat-intel scoring.
It does *not* decrypt; it is a hunt accelerator over connection metadata, so it works on
HTTPS/DoH. Scoring modifiers: periodic intervals, rare TLS signature, long/random
subdomains, low prevalence.

```bash
# Zeek -> RITA pipeline (RITA v5 runs in Docker w/ the Compose plugin)
zeek -r capture.pcap LogAscii::use_json=T          # produce conn.log, dns.log, ssl.log
git clone https://github.com/activecm/rita && cd rita
docker compose run --rm rita import /logs/ mydataset
docker compose run --rm rita view mydataset         # beacons sorted by score
# Treat RITA hits as LEADS: pivot into conn.log/ssl.log/PCAP + threat intel to confirm.
```

`scripts/beacon_hunter.py` is a self-contained beacon analyzer over Zeek `conn.log` (JSON or
TSV): it computes inter-arrival CV, payload-size dispersion, prevalence, and long-connection
flags, joins optional JA4 fingerprints, and ranks suspects — usable without RITA/Docker.

## DNS tunneling / DGA / DoH abuse (T1071.004, T1572, CWE-940)

DNS is the universal covert channel. Hunt for:

- **Query length / entropy** — encoded data in long, high-entropy subdomains (`> 50` chars,
  Shannon entropy `> 3.5`); iodine/dnscat2/DNSStager patterns.
- **TXT / NULL record volume** to one domain — data exfil channel.
- **High query volume / NXDOMAIN spikes** from one host — DGA enumeration or fast beacon.
- **Newly-registered domains** (< 30 days) — fresh C2 / DGA.
- **DoH to non-corporate resolvers** — endpoints reaching `cloudflare-dns`/`dns.google`/
  unknown DoH providers directly (bypasses internal DNS logging).

```kql
// Sentinel/Defender: high-entropy / long DNS subdomains (tunneling)
DnsEvents
| where TimeGenerated > ago(1d)
| extend sub = tostring(split(Name, ".")[0])
| extend len = strlen(sub)
| where len > 40
| extend uniq = toreal(array_length(set_difference(
        extract_all("(.)", sub), dynamic([])))) / toreal(len)   // distinct-char ratio ~ entropy proxy
| where uniq > 0.55
| summarize qcount = count(), longest = max(len) by ClientIP, Domain = tostring(split(Name,".")[-2])
| where qcount > 20
| order by qcount desc
```

`scripts/beacon_hunter.py --dns zeek_dns.log` adds Shannon-entropy and query-volume
scoring over Zeek `dns.log`.

## C2 framework signature cheat-sheet (2025)

| Framework | Net IOC | Fingerprint |
|-----------|---------|-------------|
| Cobalt Strike | `mojo.*` / default pipe names; `gate.php`/`__cfduid`; default malleable C2 profiles | JA3/JA4S families; JARM `07d...` (default) |
| Sliver | randomized TLS certs; mTLS/WireGuard/DNS listeners; `sliver` pipe prefix | **JA4X** (shared codegen) |
| Havoc | reuses Sliver cert codegen | **JA4X** ~ Sliver (diff by Org/Postal length) |
| Mythic | agent-specific (Apollo/Poseidon) HTTP profiles | JA3/JARM per profile; default ports |
| Metasploit | meterpreter stager sizes; default TLS | JA4X; JARM defaults |

Pair signatures with behavior — operators *will* customize profiles, so a JARM/JA4 hit is a
lead, confirmed by beaconing + prevalence + long-connection analysis.

## Detection (Sigma / NDR)

```yaml
title: Direct DoH to Public Resolver (DNS Logging Bypass)
id: b4c5d6e7-f8a9-0b1c-2d3e-4f5a6b7c8d9e
status: experimental
logsource: { category: proxy }
detection:
    selection:
        c-uri|contains: '/dns-query'
        cs-host:
            - 'cloudflare-dns.com'
            - 'dns.google'
            - 'doh.opendns.com'
            - 'mozilla.cloudflare-dns.com'
    filter_corp:
        src_ip|cidr: '10.0.0.0/8'   # adjust to sanctioned DoH gateways
    condition: selection and not filter_corp
level: medium
tags: [attack.command_and_control, attack.t1071.004, attack.t1572]
```

Network IOCs: connections to *IPs with no prior DNS resolution*; self-signed / short-lived
certs; uniform packet sizes on a fixed cadence; JA4 segment mismatch vs claimed UA.

## OPSEC (analyst)

- Capture at the egress choke point / TLS-terminating proxy so JA4X (TLS 1.3 certs) is
  visible; pure passive taps lose certs under TLS 1.3.
- Beacon analysis needs a long enough window — small PCAPs inflate false positives. Run over
  days of Zeek logs, not minutes.
- Do not block solely on a JA4/JARM hit; confirm with behavior to avoid blocking a legit app
  that shares a library fingerprint.

## References

- FoxIO JA4+ suite (github.com/FoxIO-LLC/ja4); "JA4+ Network Fingerprinting" — FoxIO Blog.
- "JA4 Fingerprinting: Transforming Black Boxes into Beacons for Modern Threat Hunting" — Hunt.io.
- "Advancing Threat Intelligence: JA4 fingerprints and inter-request signals" — Cloudflare, 2025.
- Active Countermeasures RITA (github.com/activecm/rita); "The Magic of RITA" — 2025.
- "C2 Detection — Command & Carol" — TryHackMe Advent of Cyber 2025 Day 22.
- C2 Matrix detection pages (howto.thec2matrix.com/detection).
- MITRE ATT&CK T1071 / T1071.004 / T1571 / T1572.
