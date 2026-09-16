# LPWAN & Sub-GHz — LoRaWAN and generic ISM

Long-range, low-power radio: **LoRaWAN** (LPWAN for sensors/asset-tracking/smart-metering) and the wider
**Sub-GHz ISM** world of OOK/ASK/FSK remotes — garage/gate openers, some car keyfobs, alarm sensors,
industrial telemetry. Adapted in part from Claude-Red (MIT) — see `THIRD-PARTY-NOTICES.md`.

> **Authorization & legality:** Sub-GHz bands (315/433/868/915 MHz etc.) are region-regulated and
> **transmitting — especially jamming — is illegal in most jurisdictions without authorization**. Replay
> against gates/vehicles/alarms has physical and legal consequences. Capture/analysis is usually passive
> and lower-risk; transmit only with explicit written scope. Radios: **RfCat** (CC1111) for OOK/ASK
> capture+replay, an **RTL-SDR** (`rtl_433`) for fingerprinting, and a **HackRF** + **Universal Radio
> Hacker (URH)** for capture→analyze→replay of arbitrary modulations; `gr-lora`/ChirpStack for LoRaWAN.

## LoRaWAN

### Keys & the version split (decides what's attackable)
- **OTAA** (over-the-air activation): device holds a root **AppKey** (1.0.x) / **AppKey + NwkKey**
  (1.1); a **Join** exchange (JoinRequest/JoinAccept) derives session keys **NwkSKey/AppSKey**.
- **ABP** (activation by personalization): session keys are **statically provisioned** — no join. ABP is
  the weak deployment: if the device **resets its frame counters** or the counters are not enforced, an
  attacker **replays uplinks/downlinks** (CWE-294), and static session keys never rotate.
- **1.0.x vs 1.1:** 1.0.x has known weaknesses — **DevNonce** was (in 1.0.1) drawn such that JoinRequests
  could be **replayed** to cause join/session desync or replay; 1.1 adds a monotonic JoinNonce/DevNonce
  scheme and split NwkKey/AppKey to fix much of it. Identify the version first.

### Attacks
| Attack | CWE | Mechanism | Note |
|--------|-----|-----------|------|
| **JoinRequest / JoinAccept replay** | CWE-294 | replay a captured OTAA join to force re-keying / desync (1.0.x) | strongest on 1.0/1.0.1; 1.1 nonce scheme mitigates |
| **ABP frame-counter / nonce reuse** | CWE-323 | counter reset (device reboot) or non-enforcement → replay uplinks & spoof downlinks | very common in cheap ABP deployments |
| **Bit-flipping without integrity gaps** | CWE-354 | if app-payload integrity relies only on NwkSKey MIC and keys are known/static | requires recovered/known session keys |
| **Eavesdrop** | CWE-319 | decrypt with recovered/leaked AppSKey (often hardcoded in firmware) | pull keys via firmware RE (-> reverse-engineering) |

```bash
# capture LoRa PHY with an SDR + gr-lora / a LoRa concentrator, or a supported dev board.
# Stand up ChirpStack (network server) in a lab to observe frame counters, join handling, dedup.
# rtl_433 also decodes many LoRa-adjacent ISM sensor protocols directly:
rtl_433 -A                       # analyze/auto-detect modulation of an unknown ISM signal
rtl_433 -F json -f 868.3M        # decode known 868 MHz device protocols to JSON
```
**Evidence bar:** observing frames is `[POSSIBLE]`; a **replayed uplink accepted by the network server**
(duplicate counter that actuates something) or a **decrypt with a recovered AppSKey** is `[CONFIRMED]`.

## Generic Sub-GHz / ISM (OOK-ASK remotes)

### Fixed-code vs rolling-code — the whole game
- **Fixed code** (cheap gates, old garage remotes, some sensors): the same symbol every press →
  **capture once, replay forever** (CWE-294). Trivial with RfCat or URH.
- **Rolling code** (KeeLoq/keyfobs, modern garage): each press is a new code from a counter+cipher, so a
  naive replay fails. Two real techniques:
  - **RollJam**: jam the receiver's band while capturing the victim's press (victim's code is *not*
    received by the target), let the victim press again (capture a 2nd), replay the *first* while holding
    the 2nd for later. Defeats rolling codes but **requires jamming** → almost always illegal without
    authorization; treat as lab/authorized-only and say so.
  - **Counter/algorithm weaknesses** (e.g. KeeLoq key-derivation weaknesses, manufacturer key reuse):
    device/firmware-specific; recover the manufacturer key via firmware RE, then predict codes.

### Capture → analyze → replay workflow
```bash
# 1. Fingerprint: frequency, modulation (OOK/ASK vs FSK), symbol timing
rtl_433 -A                                   # or inspect the waterfall in URH / gqrx

# 2. Capture with RfCat (CC1111) at the identified freq/modulation
#    (rflib/rfcat interactive: set freq, set modulation ASK/OOK, listen, save frames)

# 3. Analyze & replay in Universal Radio Hacker (URH): demodulate to bits, diff two presses
#    (identical => fixed code => replay; incrementing => rolling code => do NOT expect naive replay)
```
`scripts/rf_recon.sh subghz-id` runs `rtl_433 -A` to fingerprint before you commit a radio/modulation.

## Detection & OPSEC

- **Capture is passive and effectively undetectable** on open ISM bands — but also means *you* can't tell
  who else is listening; treat captured data as sensitive.
- **Transmit/replay/jam is detectable** by RF spectrum monitoring (rare in the field) and is the part with
  **legal exposure** — power limits, duty-cycle and band rules are region-specific. Never jam outside an
  authorized RF lab / range.
- Replay against **safety systems** (alarms, industrial actuators, vehicle entry) can cause real harm —
  scope explicitly, prefer demonstrating on a client-provided spare unit.

## What "good" looks like in a finding

- A **replayed frame that produced the effect** (gate opens, sensor spoofed, LoRaWAN uplink accepted),
  or **recovered keys** (AppSKey from firmware, manufacturer rolling-code key) with a decrypt/predict shown.
- The **exact band, modulation, and device/firmware**; "probably replayable" without a demonstrated
  action is `[POSSIBLE]`, not `[CONFIRMED]`.
