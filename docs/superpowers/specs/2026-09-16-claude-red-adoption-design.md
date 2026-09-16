# Claude-Red Adoption — Design Spec

**Date:** 2026-09-16
**Branch:** `feat/claude-red-adoption`
**Source studied:** [SnailSploit/Claude-Red](https://github.com/SnailSploit/Claude-Red) (MIT; Kai Aizen / SnailSploit,
derived in part from Sahar Shlichov's offensive-checklist) — 78 single-technique `SKILL.md` prose primers.

## Research verdict (why we adopt narrowly)

Claude-Red is a **breadth-first prose library**: good, current technique prose (real CVEs, real tooling)
but architecturally below this plugin's bar — no ATT&CK/CWE on most skills, **zero evidence-bar/confidence
discipline**, no `references/`+`scripts/` layout, inconsistent frontmatter (2 of 7 sampled aren't valid
Claude Code skills). It is a **technique quarry, not a drop-in.**

A full 78-skill checklist diff against offensive-claude shows we already match or exceed ~90% of surfaces
(AD, AI×2, API, auth, CI/CD, cloud, containers, crypto/TLS, exploit-dev, TOCTOU, forensics, fuzzing, all
infra/red-team 1:1, mobile, network, post-ex, privesc, recon, supply-chain, and most web incl. request-
smuggling via `http-desync-cache.md`). Confirmed real gaps:

| Gap | Claude-Red skills | Our status |
|-----|-------------------|------------|
| **Bluetooth (BLE + Classic)** | offensive-bluetooth-ble, offensive-bluetooth-classic | **zero** |
| **802.15.4 mesh** (Zigbee/Thread/Matter) | offensive-zigbee-thread-matter | **zero** |
| **Z-Wave** | offensive-z-wave | **zero** |
| **LoRaWAN / Sub-GHz** | offensive-lorawan-sub-ghz | **zero** |
| **Wi-Fi: KRACK/FragAttacks, WPS** | offensive-krack-fragattacks, offensive-wps | **zero** (WPA2/WPA3/evil-twin/802.1X already covered in network-attack) |
| Web depth: business-logic, HPP, file-upload | offensive-business-logic, offensive-parameter-pollution, offensive-file-upload | light (business-logic touched; HPP absent) |

## Workstreams

### WS1 — new skill `wireless-rf` (the flagship net-add: radio beyond Wi-Fi)
Owns **non-Wi-Fi RF**; Wi-Fi/WPA stays in `network-attack` (cross-referenced). Built to the full bar
(ATT&CK+CWE per technique, detection+OPSEC pairing, 2024-2026 currency, no fabricated CVEs).
- `skills/wireless-rf/SKILL.md` — thin router (When to Activate → Technique Map → Quick Start → OPSEC & Detection → Deep Dives).
- `references/bluetooth.md` — BLE (GATT enum, LE-Legacy Just-Works LTK recovery via crackle, pairing-method ID, sniffing) + Classic (KNOB CVE-2019-9506, BIAS CVE-2020-10135, BlueBorne, BleedingTooth CVE-2020-12351/12352, BLESA, SweynTooth).
- `references/mesh-iot-radio.md` — Zigbee (Touchlink commissioning reset/ZLL, key-transport, KillerBee), Thread/Matter (commissioning, OpenThread), Z-Wave (S0 key-exchange downgrade "Z-Shave", S2).
- `references/lpwan-subghz.md` — LoRaWAN 1.0.x join-accept replay + ABP counter/nonce reuse (vs 1.1), generic Sub-GHz capture/replay/rolljam (RfCat/HackRF/URH), rolling-code notes.
- `scripts/rf_recon.sh` — runnable scan/enumeration wrapper (bluetoothctl/bettercap BLE, KillerBee zbstumbler, RfCat/rtl_433), modeled on `network-attack/scripts/wifi_attack.sh`; scope/authorization banner, no destructive default.
- Wire into CLAUDE.md skill tables + README; re-pin skills-lock.

### WS2 — deepen `web-pentest` (depth we under-serve)
- `skills/web-pentest/references/business-logic-abuse.md` — state-machine modeling, price/coupon/refund/payout races, single-packet multi-request races, tenant/role boundary, anti-automation defeat (seed: Claude-Red offensive-business-logic; add CWE + our evidence tiers). ATT&CK T1539/T1078; OWASP WSTG-BUSL.
- Add HTTP Parameter Pollution (HPP) + file-upload abuse to the injection/upload references (or a short `param-pollution-upload.md`).
- Update web-pentest Technique Map + Deep Dives; keep SKILL.md <=180 lines.

### WS3 — coverage cross-reference `docs/COVERAGE-MAP.md`
Adopt Claude-Red's MINDMAP idea as a discipline artifact: a table mapping attack surface (ATT&CK
tactic / OWASP-WSTG class) → owning skill, with explicit gap flags. Not attack content — a completeness
aid complementary to `threat-model-discipline`.

## Quality bar (every new technique)
Four pillars: 2024-2026 currency with **web-search-verified, non-fabricated CVEs (mark UNVERIFIED if unsure)**;
runnable scripts (no placeholders); OPSEC + detection pairing; technique-level ATT&CK + CWE. Findings language
inherits the plugin output contract (confidence tiers, evidence-bar-by-class, feasibility tri-state). Authorized
engagements only; RF DoS/jamming techniques carry explicit scope/authorization caveats (many are illegal without
authorization and can disrupt safety systems).

## Attribution
MIT requires preserving the notice. Add `THIRD-PARTY-NOTICES.md` (or a CREDITS block) crediting
"Kai Aizen / SnailSploit — Claude-Red (MIT); derived in part from Sahar Shlichov's offensive-checklist"
for technique content adapted into the wireless-rf and web-pentest references.

## Verification
Re-pin `skills-lock.json`; run 6 consistency gates + `check_plugin_manifest` + full pytest + byte-compile +
`bash -n` + `claude plugin validate`. New skill must satisfy `check_constitution` (scope rule if it touches
targets — it does: add the forked-discipline pattern where an agent would carry it) and CSO description style.

## Deviations (honest)
RF techniques often require hardware (SDR, BLE/Zigbee adapters) so `scripts/rf_recon.sh` is a scan/enumeration
wrapper (like `wifi_attack.sh`), not a self-contained exploit. CVEs cited are well-known and real; anything
uncertain is marked UNVERIFIED rather than invented.
