# Mesh & IoT radio — Zigbee / Thread / Matter / Z-Wave

Low-rate mesh radios that run home/building automation: lights, locks, sensors, thermostats, alarm
sensors. Zigbee and Thread are **802.15.4** (2.4 GHz, and 802.15.4 also at sub-GHz); Z-Wave is a
proprietary sub-GHz mesh (868/908/916 MHz by region). Adapted in part from Claude-Red (MIT) — see
`THIRD-PARTY-NOTICES.md`.

> **Authorization & safety:** these radios control physical systems (locks, alarms, HVAC). A Touchlink
> reset can factory-reset every light in range; a replayed command can unlock a door. Confirm scope and
> get written sign-off before transmitting. Radios: a **KillerBee**-supported 802.15.4 stick (Atmel
> RZUSBstick / ApiMote) for Zigbee/Thread; an **RfCat** CC1111 dongle or an SDR (HackRF) + `gr-lora`/
> `scapy-radio`/`EZ-Wave` for Z-Wave and sub-GHz 802.15.4.

## Zigbee (802.15.4 + ZCL/ZDO)

### Trust model & the recurring bugs
- **Network key (NWK)** encrypts mesh traffic; **APS layer** can add a link key. The classic failure is
  the NWK key being **transported in the clear** during joining — older devices/Home-Automation profile
  send it encrypted only with the well-known **ZigBee Alliance default Trust Center link key**
  (`ZigBeeAlliance09`), so a sniffer that catches a join recovers the network key (CWE-319).
- **Touchlink / ZLL commissioning** (lighting): proximity commissioning that, in practice, can be driven
  from **far beyond** the intended few-cm range with a good antenna — enabling scan → identify →
  **factory-reset** / steal / re-commission of lights building-wide (CWE-284). The **ZLL master key** leak
  (2015) made ZLL inter-PAN encryption forgeable.
- Once you hold the NWK key: **decrypt, inject, and replay** NWK/APS frames (CWE-319/CWE-294).

### KillerBee workflow
```bash
zbstumbler                       # discover Zigbee networks, sweep channels 11-26, print PAN/channel
zbdump -f <chan> -w zb.pcap      # capture on a channel (feed to Wireshark: it decodes ZCL/ZDO)
zbdsniff zb.pcap                 # scan a capture for NWK keys transported in the clear (the money shot)
zbreplay -f <chan> -r zb.pcap    # replay captured frames (e.g. a "toggle"/"unlock" command)
zbgoodfind / zbwardrive          # key search / wardriving helpers
```
`scripts/rf_recon.sh zb-scan` wraps `zbstumbler`. **Evidence bar:** seeing a network is `[POSSIBLE]`;
recovering the NWK key (`zbdsniff`) or producing a device action via `zbreplay` is `[CONFIRMED]`.

## Thread / Matter (802.15.4, IPv6/6LoWPAN)

Thread is a modern 802.15.4 IP mesh; **Matter** runs application-layer on top (over Thread or Wi-Fi).
Security is much stronger than legacy Zigbee: **commissioning** uses a device passcode + ECDH (SPAKE2+),
and mesh traffic is encrypted with per-network keys. Practical attack surface is mostly:
- **Commissioning weaknesses**: a QR/numeric passcode that is guessable, reused, printed/exposed, or a
  commissioning window left open. Attacking the commissioning handshake, not the mesh crypto.
- **Implementation bugs** in the border router / OpenThread stack (memory-safety, IPv6/6LoWPAN parsing).
- Stand up **OpenThread** (`ot-cli`) + a Matter controller (`chip-tool`) in a lab to exercise
  commissioning and border-router behaviour. Treat unverified stack CVEs as UNVERIFIED until you confirm
  the exact build.

## Z-Wave (sub-GHz proprietary mesh)

- **S0 (legacy) security** uses a key exchange protected by a **hardcoded temporary key of all zeros**
  during inclusion — an attacker present at pairing recovers the network key. The **"Z-Shave"** downgrade
  (Pen Test Partners, 2018) forces a device that supports **S2** back to **S0** during inclusion, then
  exploits the S0 weakness (CWE-757 downgrade / CWE-322). *(No single CVE — cite it as the Z-Shave
  technique; confirm the controller/device firmware before claiming a device is affected.)*
- **S2** (mandated for Z-Wave Plus certification) uses ECDH (Curve25519) + out-of-band DSK and closes the
  S0 hole — so the finding usually is "device/controller still allows S0 inclusion" (downgrade) rather
  than breaking S2 itself.
- Tooling: **EZ-Wave** (HackRF/rtl-sdr + scapy-radio) and RfCat-based scripts to scan, fingerprint, and
  inject/replay Z-Wave frames; watch for command classes (Door Lock, Alarm, Switch).

## Detection & OPSEC

| Technique | IOC / telemetry | Detection | OPSEC / safety |
|-----------|-----------------|-----------|----------------|
| Zigbee join sniff → NWK key | a device joining while you capture | coordinator join/rejoin logs | passive capture is quiet; you need a *join* to happen (or force one) |
| Touchlink reset/hijack | lights resetting/leaving; inter-PAN scan/identify frames | some hubs log commissioning; 802.15.4 IDS is rare | **can reset all lights in range** — extremely disruptive; scope tight, warn the client |
| Zigbee replay/inject | duplicate frames; unexpected actuator changes | anomaly on the hub if it correlates | replaying a lock/alarm command has physical impact — authorization required |
| Z-Wave S0 downgrade | S0 inclusion where S2 expected | controller inclusion logs (S0 vs S2) | must be present during (re)inclusion; S2 defeats it |
| Sub-GHz inject/replay | in-band energy; repeated identical frames | RF spectrum monitoring (rare) | region-specific ISM band + power limits — stay legal |

## What "good" looks like in a finding

- Recovered Zigbee **NWK key** (zbdsniff) or a **device action produced by replay/injection**; for
  Touchlink, an actual reset/re-commission you triggered.
- A demonstrated **S0 downgrade** on a device that advertises S2 (show the inclusion mode), not just
  "supports S0".
- Exact controller/device firmware for any version-specific claim; otherwise `[POSSIBLE]`.
