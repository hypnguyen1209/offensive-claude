# Symmetric Cipher & AEAD Misuse

Block-cipher mode failures and authenticated-encryption misuse: ECB pattern leakage, CBC
padding oracles, CTR/GCM nonce reuse (the "forbidden attack"), and the AEAD
key-commitment gap (invisible salamanders / partitioning oracles).
ATT&CK: T1040 (Network Sniffing), T1606 (Forge Credentials). CWE-327 (Broken/Risky
Algorithm), CWE-323 (Nonce Reuse), CWE-347 (Improper Signature/Tag Verification),
CWE-209 (Information Exposure Through Error Message).

---

## 1. Theory / mechanism

| Misuse | Why it breaks |
|--------|---------------|
| **ECB** | Deterministic per-block: identical plaintext blocks → identical ciphertext blocks → structure leak, cut-and-paste forgery. |
| **CBC padding oracle** | If the server reveals (via error/timing) whether PKCS#7 padding is valid after decryption, an attacker decrypts ciphertext byte-by-byte by manipulating the previous block: 256·blocksize queries per block. |
| **CTR/GCM nonce reuse** | Keystream `= E_k(nonce‖counter)`. Reuse the nonce and `C1 ⊕ C2 = P1 ⊕ P2` (XOR of plaintexts). For **GCM** it is worse: reuse leaks the GHASH key `H`, enabling **tag forgery for arbitrary messages** ("forbidden attack"). |
| **AEAD non-commitment** | GCM, ChaCha20-Poly1305, AES-GCM-SIV, XSalsa20-Poly1305 guarantee confidentiality + integrity but **not key commitment**: one ciphertext can decrypt-and-authenticate under *two different keys*. Enables "invisible salamanders" (one blob, two valid plaintexts) and **partitioning-oracle** password recovery. |

---

## 2. Modern 2024-2026 variants (verified)

- **Key-commitment is the modern frontier.** Soatok (2024) and the NIST 3rd Block-Cipher
  Modes workshop (2023) re-emphasized that *every* polynomial-MAC AEAD (GCM, GCM-SIV,
  CCM, EAX, SIV, Poly1305 constructions) is non-committing by default.
- **Partitioning Oracle Attacks** (Len–Grubbs–Ristenpart, USENIX Security 2021) weaponize
  this: the **Multi-Collide-GCM** algorithm builds one ciphertext valid under a *set* of
  keys via polynomial interpolation, turning a "valid/invalid" oracle into a binary search
  over a password dictionary. It broke an early **OPAQUE** PAKE design and recovered
  **Shadowsocks** proxy passwords; original sims show ~20% password recovery in 18 MitM
  impersonations.
- Follow-on: Menda–Len–Grubbs–Ristenpart (2023) "Context Discovery and Commitment
  Attacks: How to Break CCM, EAX, SIV, and More"; 2024 work targets **TLS session
  tickets** as a partitioning-oracle surface.
- Mitigations now shipping: **`age`** file encryption and the **HPKE** internet-draft added
  key-committing constructions; the fix is a committing AEAD (e.g., AES-GCM + key-commitment
  tag, or use of `AES-GCM-SIV` only with a commitment wrapper).

Sources: soatok.blog/2024/09/10 "Invisible Salamanders Are Not What You Think";
usenix.org/system/files/sec21-len.pdf (Partitioning Oracle Attacks); NIST CSRC "Practical
Challenges with AES-GCM"; Menda et al. (2023) commitment attacks.

---

## 3. Complete working code

Two scripts back this cluster:
`scripts/padding_oracle.py` (CBC byte-by-byte decrypt + encrypt) and
`scripts/gcm_nonce_reuse.py` (forbidden-attack GHASH-key recovery + tag forgery + a
key-commitment / multi-collide demonstration). Core forbidden-attack math:

```python
# AES-GCM forbidden attack: two ciphertexts under SAME (key, nonce) -> recover GHASH key H.
# GHASH operates in GF(2^128). The auth tag is a polynomial in H evaluated over the
# ciphertext blocks + length block. Two tags give a polynomial whose roots are candidate H.
def recover_H_candidates(c1, t1, c2, t2):
    """c1/c2: ciphertext byte strings (same len, same nonce); t1/t2: 16-byte tags.
    Returns candidate values of the GHASH subkey H (GF(2^128) field elements)."""
    p1 = _ghash_poly(c1, t1)     # coefficients in GF(2^128)
    p2 = _ghash_poly(c2, t2)
    diff = _poly_add(p1, p2)     # XOR of the two GHASH polynomials -> known poly in H
    return _poly_roots_gf2_128(diff)   # roots = H candidates (forge tags with each)
```
The script includes a complete GF(2^128) implementation (carry-less multiply, modular
reduction by the GCM polynomial `x^128 + x^7 + x^2 + x + 1`) and a root-finder, so it runs
standalone. CBC oracle driver (live HTTP):

```bash
python3 scripts/padding_oracle.py decrypt \
  --url https://target/api/decrypt --param token --ct $B64_CT --block 16 \
  --oracle-string 'PaddingException'           # body substring meaning "bad padding"
# Forge a chosen plaintext (encrypt) from the same oracle:
python3 scripts/padding_oracle.py encrypt --url ... --plaintext '{"admin":true}'
```

### ECB / nonce-reuse quick checks
```bash
# ECB detection: hex-dump ciphertext, look for repeated 16-byte blocks
python3 scripts/gcm_nonce_reuse.py ecb-detect ciphertext.bin --block 16
# CTR/GCM nonce reuse: XOR two captured ciphertexts -> P1 ^ P2 (crib-drag to recover)
python3 scripts/gcm_nonce_reuse.py xor ct1.bin ct2.bin > p1_xor_p2.bin
```

---

## 4. Detection

```yaml
title: CBC Padding Oracle Probing
id: cbc-padding-oracle
logsource: { category: webserver }
detection:
  burst:
    cs-uri-stem|endswith: '/decrypt'
    sc-status: [400, 500]
  cond: burst | count() by c-ip > 2000 within 10m
  condition: burst and cond
level: high
```
- **Padding oracle:** ~256×blocks×messages requests to one decrypt endpoint, alternating
  4xx/2xx — classic burst signature; Sigma on the rate is reliable.
- **Nonce reuse / GCM:** offline once two ciphertexts are captured; defensive detection is
  a code/crypto audit flagging reused IVs or random nonces with a 96-bit space under high
  volume. Log and alert on duplicate `(key_id, nonce)` pairs if the app records them.
- **Partitioning oracle:** repeated decrypt attempts with attacker-crafted multi-key blobs;
  monitor for unusually large/odd ciphertexts and high failed-auth volume on PAKE/ticket
  endpoints.

---

## 5. OPSEC

- CBC padding-oracle attacks are **extremely loud** (tens of thousands of requests) — set a
  query budget, randomize timing, and confirm scope; abort if the endpoint rate-limits.
- GCM forbidden-attack and key-commitment exploitation are **offline** after capturing the
  ciphertext(s)/tag(s) — no target noise during the math.
- Multi-collide / partitioning-oracle attacks against live PAKE/Shadowsocks endpoints are
  interactive (MitM impersonations) and detectable; only against authorized targets.
- Cleanup: padding-oracle traffic is in web logs you cannot scrub — document the window.

---

## 6. References
- "Invisible Salamanders Are Not What You Think" — https://soatok.blog/2024/09/10/invisible-salamanders-are-not-what-you-think/
- Len, Grubbs, Ristenpart, "Partitioning Oracle Attacks", USENIX Security 2021 — https://www.usenix.org/system/files/sec21-len.pdf
- Menda, Len, Grubbs, Ristenpart (2023), "Context Discovery and Commitment Attacks…"
- NIST CSRC, "Practical Challenges with AES-GCM"
- Joux, "Authentication Failures in NIST version of GCM" (forbidden attack, 2006)
- Vaudenay (2002), CBC padding oracle
