#!/usr/bin/env bash
# rf_recon.sh - non-Wi-Fi RF reconnaissance/enumeration driver: BLE discovery + GATT enumeration,
# Zigbee/802.15.4 network discovery, and Sub-GHz/ISM signal fingerprinting.
#
# SCOPE: recon/enumeration ONLY. This script does not transmit attack frames, jam, replay, or write to
#   devices by default. The one action that touches a peripheral (ble-enum) performs read-only GATT
#   discovery + read of a handle you pass explicitly. Actual exploitation (crackle, zbreplay, RollJam,
#   URH replay) is deliberately left to the operator per-technique, under written authorization, because
#   it has physical impact. See references/*.md.
#
# USAGE:
#   ./rf_recon.sh ble-scan                         # discover BLE advertisers
#   ./rf_recon.sh ble-enum   <BD_ADDR> [handle]    # GATT services/characteristics (+ optional read)
#   ./rf_recon.sh zb-scan                          # discover Zigbee/802.15.4 networks (KillerBee)
#   ./rf_recon.sh subghz-id  [freq]                # fingerprint an ISM signal (rtl_433 analyze)
#
# DEPENDENCIES (install per technique; the script checks and tells you what is missing):
#   BLE:     bluez (bluetoothctl/hcitool/gatttool) and/or bettercap
#   Zigbee:  killerbee (zbstumbler) + a supported 802.15.4 radio (RZUSBstick/ApiMote)
#   Sub-GHz: rtl_433 + an RTL-SDR (or HackRF)
#
# OPSEC / LEGAL: RF crosses walls and property lines. Confirm the target device/band is IN SCOPE and that
#   you have written authorization BEFORE running anything here. Even passive capture of others' traffic
#   may be regulated in your jurisdiction. Transmitting/jamming without authorization is illegal.

set -euo pipefail

MODE="${1:-}"; shift || true

_need() {
    # _need <binary> <hint> ; returns non-zero (and warns) if the tool is absent
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "[!] missing '$1' - install it ($2) and re-run" >&2
        return 1
    fi
}

_authz_banner() {
    echo "=============================================================================="
    echo " rf_recon.sh - AUTHORIZED RF assessment only. Confirm the target/band is in"
    echo " scope (scope.json) and you have written authorization. RF reaches neighbours."
    echo "=============================================================================="
}

ble_scan() {
    _authz_banner
    if command -v bettercap >/dev/null 2>&1; then
        echo "[*] BLE recon via bettercap (20s)..."
        sudo bettercap -eval "ble.recon on; sleep 20; ble.show; ble.recon off; q"
    elif _need hcitool "apt install bluez"; then
        echo "[*] BLE scan via hcitool (Ctrl-C to stop)..."
        sudo hcitool lescan --duplicates
    else
        return 1
    fi
}

ble_enum() {
    local ADDR="${1:?BD_ADDR required (see ble-scan output)}"
    local HANDLE="${2:-}"
    _authz_banner
    _need gatttool "apt install bluez" || return 1
    echo "[*] Primary services on $ADDR:"
    gatttool -b "$ADDR" --primary || true
    echo "[*] Characteristics (note the 'props' - Write/WriteWithoutResponse without pairing = candidate):"
    gatttool -b "$ADDR" --characteristics || true
    if [ -n "$HANDLE" ]; then
        echo "[*] Reading handle $HANDLE (read-only):"
        gatttool -b "$ADDR" --char-read -a "$HANDLE" || true
    fi
    echo "[i] To test an unauthenticated write (impact proof), do it explicitly & in scope:"
    echo "    gatttool -b $ADDR --char-write-req -a <handle> -n <hexvalue>"
}

zb_scan() {
    _authz_banner
    _need zbstumbler "pip install killerbee (+ a supported 802.15.4 radio)" || return 1
    echo "[*] Zigbee/802.15.4 discovery across channels 11-26..."
    sudo zbstumbler
}

subghz_id() {
    local FREQ="${1:-}"
    _authz_banner
    _need rtl_433 "apt install rtl-433 (+ an RTL-SDR)" || return 1
    if [ -n "$FREQ" ]; then
        echo "[*] Decoding known ISM device protocols at $FREQ (JSON)..."
        rtl_433 -F json -f "$FREQ"
    else
        echo "[*] Auto-analyzing modulation/timing of an unknown ISM signal (rtl_433 -A)..."
        rtl_433 -A
    fi
}

case "$MODE" in
    ble-scan)   ble_scan ;;
    ble-enum)   ble_enum "$@" ;;
    zb-scan)    zb_scan ;;
    subghz-id)  subghz_id "$@" ;;
    *)
        echo "usage: $0 {ble-scan|ble-enum <BD_ADDR> [handle]|zb-scan|subghz-id [freq]}" >&2
        exit 2
        ;;
esac
