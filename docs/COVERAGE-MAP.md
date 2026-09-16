# Coverage Map — attack surface → owning skill

A cross-reference from attack surface (ATT&CK tactic / OWASP-WSTG class / protocol) to the skill that
owns it, with an honest **gap ledger**. Use it the way you'd use a pre-engagement checklist: walk the row
for each surface in scope and confirm a skill exists; a blank cell is a gap in the *engagement plan*, not
just the repo. Complements `threat-model-discipline` (which models a specific target) — this maps the
whole framework. Idea adapted from Claude-Red's `MINDMAP.md` (MIT).

> Keep this in sync when skills are added/removed. `check_plugin_manifest.py` does not police this file;
> it is a human-maintained discipline artifact.

## By kill-chain phase / ATT&CK tactic

| Phase / Tactic | Surface | Owning skill(s) |
|----------------|---------|-----------------|
| Recon (TA0043) | OSINT, subdomains, attack-surface, CVE prioritization | `recon-osint` |
| Recon / Analysis | Source-code audit, taint, variant hunting | `vulnerability-analysis` |
| Weaponize (TA0042) | PoC/payload/shellcode dev | `exploit-development`, `shellcode-dev` |
| Weaponize | Binary/firmware RE, protocol RE | `reverse-engineering` |
| Delivery (TA0001) | Phishing, payload delivery, HTML smuggling | `initial-access` |
| Delivery/Exploit | Web app & API | `web-pentest` |
| Exploit (TA0002) | Mitigation bypass (ASLR/DEP/CFG/CET) | `windows-mitigations` |
| Exploit | Security-boundary / sandbox escape | `windows-boundaries`, `container-k8s-escape` |
| Exploit | Browser / client-side (V8, Electron) | `browser-exploitation` |
| PrivEsc (TA0004) | Linux / Windows local privesc | `privesc-linux`, `privesc-windows` |
| Persistence/Install (TA0003) | Persistence, EDR/AV evasion | `red-team-ops`, `edr-evasion` |
| Lateral/Actions (TA0008/TA0040) | Network & AD, lateral movement | `network-attack`, `active-directory-attack` |
| C2 (TA0011) | C2 infra, staged payloads, OPSEC | `advanced-redteam` |
| Collection (TA0009) | Input capture / keylogging | `keylogger-arch` |
| Cross-cutting | Cloud attack paths | `cloud-security` |
| Cross-cutting | Cryptographic assessment | `crypto-analysis` |
| Cross-cutting | AI/ML & agentic/LLM app red-team | `ai-security`, `ai-agent-redteam` |
| Cross-cutting | CI/CD & supply chain | `cicd-supply-chain` |
| Cross-cutting | Mobile (Android/iOS) | `mobile-pentest` |
| Report (TA0040) | Malware RE, IR/forensics, detection/hunting | `malware-analysis`, `incident-response`, `threat-hunting` |
| Support | Cross-engagement pattern learning | `engagement-memory` |

## Web (OWASP-WSTG) — owned by `web-pentest` references

| Class | Reference |
|-------|-----------|
| Injection (SQLi/NoSQL/cmdi), HPP, file-upload | injection-sqli-cmdi.md |
| XSS / CSP / client-side prototype pollution | xss-csp-clientside.md |
| SSRF / cloud metadata | ssrf-cloud-metadata.md |
| Request smuggling / desync / cache poisoning | http-desync-cache.md |
| SSTI / deserialization / SSPP | ssti-deserialization.md |
| AuthN/AuthZ: JWT/OAuth/SAML/GraphQL/IDOR/BOLA/race | auth-api-access-control.md |
| Business-logic abuse | business-logic-abuse.md |

## Wireless / RF

| Surface | Owning skill / reference |
|---------|--------------------------|
| Wi-Fi: WPA2/PMKID, WPA3-Transition downgrade, evil-twin/802.1X, KRACK/FragAttacks, WPS | `network-attack` → references/wireless-attacks.md |
| Bluetooth (BLE + Classic: GATT, crackle, KNOB/BIAS/BleedingTooth) | `wireless-rf` → references/bluetooth.md |
| Zigbee / Thread / Matter / Z-Wave (Touchlink, key-in-clear, S0 downgrade) | `wireless-rf` → references/mesh-iot-radio.md |
| LoRaWAN / Sub-GHz / ISM (join replay, ABP reuse, OOK-ASK replay/rolljam) | `wireless-rf` → references/lpwan-subghz.md |

## Gap ledger (honest — what is NOT yet covered)

| Gap | Status / note |
|-----|---------------|
| **macOS offensive** (TCC/Gatekeeper/Keychain) | *planned* — `macos-offensive` listed but not yet built |
| **Smart-contract / web3 / EVM** | not covered here (the separate `vuln-research` suite has it) |
| **Automotive / CAN bus** | not covered |
| **ICS / OT / SCADA** (Modbus, DNP3, S7) | not covered |
| **NFC / RFID / contactless** | not covered (BLE/sub-GHz are, in `wireless-rf`) |
| **GNSS / GPS spoofing, satellite** | not covered |
| **IoT firmware depth** | partial — `reverse-engineering` covers firmware RE; no dedicated IoT-device skill |

Adding any of these follows `writing-offensive-skills` (thin router + references/ + scripts/, ATT&CK+CWE
per technique, detection+OPSEC pairing, evidence bars). Update this map and re-pin `skills-lock.json`.
