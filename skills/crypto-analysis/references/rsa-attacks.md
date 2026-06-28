# RSA Weak-Key Attacks

Recover RSA private keys (or decrypt ciphertexts) from weak public keys and bad
parameter choices. Applies to CTF crypto, key-hygiene auditing of fleets, and real
incidents (Debian OpenSSL, ROCA, Fermat-close primes).
ATT&CK: T1600 (Weaken Encryption). CWE-326 (Inadequate Encryption Strength),
CWE-310 (Cryptographic Issues), CWE-327 (Broken/Risky Crypto Algorithm).

---

## 1. Theory / mechanism

RSA: `n = p·q`, `e·d ≡ 1 (mod φ(n))`, `c = m^e mod n`. Security rests on factoring `n`.
Every attack below either factors `n` cheaply because the primes were chosen badly, or
recovers `m`/`d` because of structural parameter misuse.

| Attack | Precondition | Mechanism |
|--------|-------------|-----------|
| Fermat factorization | `p ≈ q` (close primes) | `a = ceil(sqrt(n))`, test `a²−n` perfect square; few iters when gap is small |
| Trial / small-q | tiny prime factor | sieve small primes, factordb lookup |
| Wiener | small `d` (`d < n^0.25/3`) | continued-fraction convergents of `e/n` reveal `d` |
| Boneh–Durfee | `d < n^0.292` | lattice extension of Wiener (Coppersmith) |
| Common modulus | same `n`, coprime `e1,e2`, same `m` | Bezout: `m = c1^a · c2^b mod n` |
| Hastad broadcast | same `m` sent to `e` recipients, low `e` | CRT → `m^e mod ∏n_i`, then integer `e`-th root |
| Coppersmith partial-key | ≥50% bits of `p` (or high bits of `m`) known | `small_roots` on a modular polynomial |
| ROCA (CVE-2017-15361) | RSALib (Infineon) keys, structured primes | Coppersmith over the discrete-log structure of `p` |
| Batch-GCD | corpus of keys sharing a prime | pairwise `gcd(n_i, n_j) > 1` factors both |

---

## 2. Modern 2024-2026 variants (verified)

- **ROCA / CVE-2017-15361** is still a *recommended baseline check*. A 2025 study of SSH
  client signatures (arxiv 2509.09331) detects ROCA keys "with a negligible false-positive
  rate" using the original authors' tooling, and CA/Browser guidance still lists ROCA,
  Debian weak keys, and **Fermat weak keys (Böck, 2023)** as mandatory key-hygiene checks.
- **Fermat-close primes** remain a live finding class (Böck's 2022/2023 scans found
  vulnerable keys in shipping printers/firewalls) — always run Fermat first; it is O(gap).
- **Tooling reality (2026):** `RsaCtfTool` bundles ~30 attacks (Fermat, Wiener,
  boneh_durfee, roca, neca, hastads, same_n_huge_e, ecm, siqs, partial_q…). For real
  factoring it delegates to **cado-nfs / yafu / msieve**; for Coppersmith/LLL `small_roots`
  it requires **SageMath**. Expect environment friction (stale Docker images).

Sources: github.com/RsaCtfTool/RsaCtfTool; arxiv.org/html/2509.09331v1 (SSH client sig
study, 2025); Nemec et al. "Return of Coppersmith's Attack" (ROCA, CCS 2017); Böck Fermat
factorization advisory (2023).

---

## 3. Complete working code

The full driver is `scripts/rsa_attack.py` (pure-Python: Fermat, Wiener, common-modulus,
Hastad, batch-GCD, ROCA fingerprint; optional Sage hand-off). Core routines, standalone:

```python
from math import isqrt, gcd

def fermat(n, max_iter=1_000_000):
    a = isqrt(n)
    if a * a < n: a += 1
    for _ in range(max_iter):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            return a - b, a + b          # p, q
        a += 1
    return None

def wiener(e, n):
    # continued fraction of e/n; each convergent k/d is a candidate
    def cf(x, y):
        while y:
            q = x // y; yield q; x, y = y, x - q * y
    def convergents(seq):
        n0, n1, d0, d1 = 0, 1, 1, 0
        for q in seq:
            n0, n1 = n1, q * n1 + n0
            d0, d1 = d1, q * d1 + d0
            yield n1, d1
    for k, d in convergents(cf(e, n)):
        if k == 0: continue
        if (e * d - 1) % k: continue
        phi = (e * d - 1) // k
        s = n - phi + 1                 # p+q
        disc = s * s - 4 * n
        if disc >= 0 and isqrt(disc) ** 2 == disc:
            return d                    # private exponent recovered
    return None

def common_modulus(c1, c2, e1, e2, n):
    # m = c1^a * c2^b mod n  where a*e1 + b*e2 = 1
    g, a, b = _egcd(e1, e2)
    assert g == 1, "exponents must be coprime"
    inv = lambda x: pow(x, -1, n)
    m = (pow(c1, a, n) if a >= 0 else pow(inv(c1), -a, n)) * \
        (pow(c2, b, n) if b >= 0 else pow(inv(c2), -b, n))
    return m % n

def _egcd(a, b):
    if b == 0: return a, 1, 0
    g, x, y = _egcd(b, a % b); return g, y, x - (a // b) * y

def batch_gcd(moduli):
    # naive O(k^2) pairwise GCD — finds shared primes across a key corpus
    found = {}
    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            g = gcd(moduli[i], moduli[j])
            if 1 < g < moduli[i]:
                found[i] = g; found[j] = g
    return found   # index -> shared prime factor
```

### Operational workflow
```bash
# 1. Fast structural triage (our tool — no Sage needed)
python3 scripts/rsa_attack.py --pubkey key.pem --auto
#    -> reports Fermat hit, Wiener d, ROCA fingerprint, small factors

# 2. If ROCA fingerprint positive:
git clone https://github.com/crocs-muni/roca && python3 roca/roca/detect.py key.pem
#    then neca / RsaCtfTool roca attack for full factorization

# 3. Coppersmith partial-key (needs SageMath):
sage scripts/rsa_attack.py --coppersmith --pubkey key.pem --known-high 0xDEAD... 
#    (script shells to sage and uses small_roots)

# 4. Industrial factoring fallback:
RsaCtfTool.py -n $N -e $E --uncipher $C       # bundles cado-nfs/yafu/msieve hand-off
```

---

## 4. Detection

RSA weak-key attacks are **offline** once you hold the public key/ciphertext — there is no
target-side telemetry during factoring. Defensive detection is *key hygiene at issuance*:

```yaml
title: Weak RSA Key Issued / In Use
id: rsa-weakkey-hygiene
logsource: { product: pki_ca }
detection:
  small_key:   { key_algorithm: 'RSA', key_size: '< 2048' }
  fermat_risk: { note: 'primes within 2^512 of each other (run Boeck fermat-test)' }
  roca_risk:   { note: 'RSALib fingerprint positive (Infineon TPM/smartcard)' }
  condition: small_key or fermat_risk or roca_risk
level: high
```
Practical defensive scan: run `roca-detect`, a Fermat test, and batch-GCD across every
RSA modulus in the certificate/SSH-key inventory (the same code in `rsa_attack.py`).

---

## 5. OPSEC

- Acquisition of public keys (TLS certs, SSH `authorized_keys`, JWKS, blockchain) is
  passive; factoring runs entirely on your own hardware — zero footprint on target.
- Long factoring jobs (cado-nfs) are resource-heavy — run on isolated infra, not the
  client's network.
- If you recover a private key, treat it as crown-jewel loot: encrypt at rest, restrict to
  the engagement vault, and include rotation guidance in the finding.

---

## 6. References
- RsaCtfTool: https://github.com/RsaCtfTool/RsaCtfTool
- ROCA: Nemec, Sys, Svenda, Klinec, Matyas, "The Return of Coppersmith's Attack" (CCS 2017); CVE-2017-15361; https://github.com/crocs-muni/roca
- Fermat weak keys (Böck, 2023) — fermatattack.secvuln.info
- "On the Security of SSH Client Signatures" — https://arxiv.org/html/2509.09331v1 (2025)
- Wiener (1990); Boneh–Durfee (1999); Coppersmith (1996); Hastad (1988)
