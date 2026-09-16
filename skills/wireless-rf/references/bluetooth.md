# Bluetooth — BLE & Classic

Attacking Bluetooth Low Energy (GATT/SMP) and Bluetooth Classic (BR/EDR). BLE is where most modern IoT
lives (locks, wearables, medical, trackers); Classic still carries audio, HID, file transfer and legacy
peripherals. Adapted in part from Claude-Red (MIT) — see `THIRD-PARTY-NOTICES.md`.

> **Authorization:** Bluetooth reaches through walls to neighbouring devices. Confirm the *specific*
> device is in scope before you connect, pair, or transmit. Crashing a stack (BlueBorne/BleedingTooth)
> is a DoS — lab-validate and get written sign-off. Radios: a dual-mode adapter for connect/enumerate,
> plus a **Sniffle** (TI CC26x2) or **Ubertooth One** / **nRF52 + btlejack** for over-the-air capture.

## BLE data model — what you are attacking

A BLE peripheral exposes a **GATT** table: Services → Characteristics → Descriptors, each with
permissions (Read/Write/Notify/Indicate) and an optional security requirement (none / encryption /
authenticated pairing). The two recurring bug classes:

1. **Missing authorization on a sensitive characteristic** (CWE-306): a "unlock", "set-PIN", "firmware"
   or "factory-reset" characteristic that is writable with *no* pairing/encryption requirement. This is
   the single most common real-world BLE finding.
2. **Weak pairing** (CWE-322): **LE Legacy** pairing (Just Works / 6-digit Passkey / OOB) derives a
   short-term key from a guessable/none TK; a passive sniff of the pairing lets **crackle** recover the
   STK→LTK. **LE Secure Connections** (BLE 4.2+, P-256 ECDH) defeats this — confirm which is in use.

### Enumerate the GATT and flag the bugs

```bash
# discover advertisers (passive-ish)
sudo hcitool lescan --duplicates
sudo bettercap -eval "ble.recon on; sleep 20; ble.show; ble.recon off"

# full GATT dump + permissions (gatttool is legacy but explicit; bleak for scripting)
gatttool -b <BD_ADDR> --primary                 # services
gatttool -b <BD_ADDR> --characteristics          # characteristics + handles + properties
gatttool -b <BD_ADDR> --char-read  -a 0x002a     # read a handle
gatttool -b <BD_ADDR> --char-write-req -a 0x0025 -n 01   # write (probe for unauth control)
```

`scripts/rf_recon.sh ble-enum <BD_ADDR>` wraps this and highlights **writable characteristics that
succeeded without pairing** — those are your candidates. **Evidence bar:** an advertised/writable
characteristic is only `[POSSIBLE]`; you reach `[CONFIRMED]` when the write produces the physical/logical
effect (lock opens, PIN changes, telemetry leaks) or you recover a key — see `finding-discipline`.

### Identify the pairing method (decides feasibility)

- Sniff a fresh pairing with Sniffle/Ubertooth to a pcap while the phone app connects.
- LE Legacy Just Works / Passkey → `crackle -i pairing.pcap` recovers the LTK/STK in seconds.
  With the LTK you decrypt all future traffic and can clone the central.
- LE Secure Connections → crackle cannot; pivot to companion-app RE (the app may hold a shared secret,
  a cloud token, or implement the "security" in software above an open GATT).

```bash
crackle -i pairing.pcap                 # prints LTK if LE Legacy
# decrypt a captured session with a known LTK:
crackle -i traffic.pcap -o decrypted.pcap -l <LTK>
```

### Active MITM / relay

`btlejack -c <access_address>` can follow, jam and **hijack** an existing BLE connection (nRF52840).
For a relay (e.g. proximity-unlock car/lock), two radios relay GATT between victim central and peripheral;
LE Secure Connections does not stop a pure relay (it is a distance/relay problem, not a crypto one) —
note this in findings, and that timing/distance-bounding is the real mitigation.

### Companion-app RE (when the radio is locked down)

Pull the app and read the pairing/command logic — the "protection" is often in the app, not the radio:
```bash
adb shell pm path com.vendor.app && adb pull <path>/base.apk    # then JADX/apktool (-> reverse-engineering)
```
Look for: hardcoded keys/HMAC secrets, an "open GATT + app-layer auth" pattern (bypassable by talking to
the GATT directly), and cloud tokens. Hand deep RE to `reverse-engineering` / `mobile-pentest`.

## Bluetooth Classic (BR/EDR)

| Attack | CVE / ref | What it does | Reality check |
|--------|-----------|--------------|---------------|
| **KNOB** | CVE-2019-9506 | Negotiate encryption-key **entropy down to 1 byte**, then brute the key | Needs to be present during key setup + proximity; patched hosts enforce a min entropy (7+ bytes). CWE-326. |
| **BIAS** | CVE-2020-10135 | Impersonate a previously-paired device without the link key (master/slave role + no mutual auth) | Often chained with KNOB (KNOB+BIAS). Patched stacks require mutual authentication. CWE-287. |
| **BlueBorne** | CVE-2017-1000251 (BlueZ), CVE-2017-0781/0782 (Android) | Stack memory-corruption reachable **without pairing** → RCE/DoS | Old but still found on unpatched embedded Linux/Android. CWE-787/119. DoS risk. |
| **BleedingTooth** | CVE-2020-12351, CVE-2020-12352, CVE-2020-24490 | Linux BlueZ L2CAP/A2MP/HCI heap issues → RCE/info-leak, and an advertising-side overflow | Kernel-level; verify BlueZ/kernel version. Crash/DoS risk — lab only. |
| **BLESA** | (spoofing class, no single CVE) | Spoofing on **reconnection** because the client doesn't re-authenticate the server after bonding | Design/impl weakness; affects many BLE clients. |
| **SweynTooth** | family (multiple vendor CVEs) | SoC BLE stack crashes/deadlocks/security-bypass (Cypress/NXP/TI/Dialog/etc.) | Device-specific; mark the exact vendor CVE UNVERIFIED until you confirm the SoC + firmware. |

```bash
# classic recon
sudo hcitool scan ; sudo sdptool browse <BD_ADDR>        # discoverable devices + SDP services
# KNOB/BIAS require tooling that manipulates pairing (e.g. the researchers' PoCs / internalblue on
# supported dongles). Confirm the host stack patch date first — most modern phones/laptops are fixed.
```

## Detection & OPSEC

- **Passive first:** advertising capture and GATT reads look like a normal client; they rarely alert.
- **Active writes / re-pairing / MITM** are what get noticed by a well-instrumented companion app
  (unexpected value changes, duplicate BD_ADDR, RSSI jumps from a 2nd radio).
- **BLE has no widespread WIDS** analogous to Wi-Fi — detection usually lives in the app/backend, not the
  air. Say so honestly in the report; don't overstate stealth.
- **Crashing tests (BlueBorne/BleedingTooth/SweynTooth) are DoS** — only in a lab, on a device you may
  brick, with written authorization.

## What "good" looks like in a finding

- Recovered LTK (crackle output) + a decrypted session, **or** an unauthenticated write that produced the
  device effect, **or** a confirmed KNOB/BIAS downgrade with the negotiated entropy shown.
- Exact stack/SoC + firmware version for any CVE claim (RF CVEs are highly version-specific — an
  unversioned "vulnerable to BlueBorne" is `[POSSIBLE]`, not `[CONFIRMED]`).
