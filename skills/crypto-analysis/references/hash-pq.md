# Hash Cracking, KDF Strength & Post-Quantum Readiness

Two coupled topics: offensive password/hash recovery (identification, GPU economics, KDF
grading) and forward-looking post-quantum exposure assessment ("harvest now, decrypt
later"). Both are about *how long a secret stays secret*.
ATT&CK: T1110.002 (Brute Force: Password Cracking), T1600 (Weaken Encryption).
CWE-916 (Weak Password Hash / Insufficient Computational Effort), CWE-327 (Broken/Risky
Crypto Algorithm), CWE-326 (Inadequate Encryption Strength).

---

## 1. Theory / mechanism

**Hash cracking** = identify the algorithm, then run dictionary / rule / mask / brute on
GPUs. The single biggest lever is *whether the storage scheme is a fast hash or a
memory-hard KDF*:

- **Fast hashes** (MD5, SHA-1, SHA-256, NTLM, raw-keccak): billions–tens-of-billions of
  guesses/sec per GPU → effectively any human password falls.
- **Memory-hard / iterated KDFs** (bcrypt, scrypt, Argon2id, PBKDF2 w/ high iters): designed
  to resist GPU parallelism → orders of magnitude slower, defensible if cost is high enough.

**Post-quantum exposure**: Shor's algorithm breaks RSA/ECC/DH once a cryptographically
relevant quantum computer exists. The active threat *today* is **Harvest Now, Decrypt
Later (HNDL)** — adversaries record encrypted traffic now to decrypt later. Any secret with
a confidentiality lifetime past ~2030 is in scope.

---

## 2. Modern 2024-2026 facts (verified)

### Cracking economics
- **RTX 4090** (hashcat v6.2.6): ~300 GH/s NTLM, ~200 kH/s bcrypt (OC) — >2× the 3090.
- **RTX 5090** (Blackwell, 2025): ~3,800 kH/s WPA2 (~46% over 4090); ~65% faster on bcrypt.
- **bcrypt cost reality:** hashcat's `-m 3200` benchmark uses **cost factor 5**, which is
  no longer realistic — strong deployments in 2025 use **cost 10+** (≥1024 iterations).
  Argon2id and bcrypt remain effective GPU brakes; fast hashes do not.
- hashcat mode quick-ref (still current):
  `0`=MD5, `100`=SHA1, `1400`=SHA256, `1700`=SHA512, `1800`=sha512crypt, `3200`=bcrypt,
  `1000`=NTLM, `5600`=NetNTLMv2, `13100`=Kerberoast (RC4), `19600/19700`=Kerberoast (AES),
  `18200`=AS-REP, `22000`=WPA-PBKDF2 (replaces 2500/16800), `16500`=JWT HS,
  `34000`=Argon2 (modern builds).

### Post-quantum (NIST finalized Aug 14 2024)
- **FIPS 203 = ML-KEM** (Kyber) — KEM, replaces RSA/ECDH key establishment.
- **FIPS 204 = ML-DSA** (Dilithium) — signatures, replaces ECDSA/RSA in certs/tokens.
- **FIPS 205 = SLH-DSA** (SPHINCS+) — hash-based signature backup.
- **Hybrid TLS 1.3** combining **X25519 + ML-KEM-768** is *already in production* in major
  browsers/CDNs (advertised in the `supported_groups` extension); ANSSI/BSI recommend
  hybrid now; NSA CNSA 2.0 mandates PQC for NSS by 2025, exclusive by 2035.
- NIST IR 8547 (transition guidance): ML-KEM is the only approved PQ key-establishment.
- Operational bottleneck = **crypto-agility**; HSMs gaining ML-KEM/ML-DSA support 2025-26.

Sources: gist Chick3nman hashcat v6.2.6 RTX 4090; onlinehashcrack/ tutorials.technology
GPU benchmark tables 2025-26; specopssoft bcrypt RTX 5090 research; NIST FIPS
203/204/205 (Aug 2024); NIST IR 8547; CSA "AI Infrastructure PQ — Harvest Now Decrypt
Later"; Palo Alto NIST PQC migration guide.

---

## 3. Complete working code & commands

`scripts/hash_triage.py` identifies hashes (regex + entropy heuristics), maps to hashcat
`-m` / john format, grades KDF strength, and emits a crack plan. PQ posture is read by
`scripts/tls_audit.py` (checks negotiated group for ML-KEM hybrids).

```bash
# 1. Identify + plan
python3 scripts/hash_triage.py hashes.txt
#   -> per hash: type guess, hashcat -m, john --format, "fast/slow" verdict, cost estimate

# 2. Crack — fast hash, rules
hashcat -m 1000 ntlm.txt rockyou.txt -r rules/best64.rule -O -w 3      # NTLM
hashcat -m 22000 capture.hc22000 wordlist.txt -r rules/dive.rule       # WPA2
hashcat -m 19700 kerb.txt wordlist.txt                                 # Kerberoast AES
hashcat -m 16500 token.jwt wordlist.txt                                # JWT HS secret

# 3. Mask attacks (pattern brute)
hashcat -m 0 md5.txt -a 3 'Company?d?d?d?d'        # Company0000-9999
hashcat -m 0 md5.txt -a 3 ?u?l?l?l?l?d?d?d?s        # Ullllddd!

# 4. Slow KDF — budget realistically; cost matters
hashcat -m 3200 bcrypt.txt wordlist.txt            # bcrypt: GH/s -> kH/s, plan accordingly

# 5. PQ / HNDL posture of a TLS endpoint
python3 scripts/tls_audit.py target.com:443 --pq    # flags X25519MLKEM768 vs classical-only

# Common patterns to seed wordlists/rules:
#   Season+Year (Summer2025!), Company+digits, keyboard walks (!QAZ2wsx)
```

KDF strength grading logic (in `hash_triage.py`):
```python
def grade_kdf(scheme, params):
    if scheme in ('md5', 'sha1', 'sha256', 'ntlm', 'sha512'):
        return 'CRITICAL: fast hash for passwords (CWE-916) — billions/sec on one GPU'
    if scheme == 'bcrypt':
        cost = params.get('cost', 5)
        return ('OK' if cost >= 12 else
                f'WEAK: bcrypt cost {cost} (<12); 2025 baseline is 10-12+')
    if scheme == 'pbkdf2':
        it = params.get('iterations', 0)
        return 'OK' if it >= 600_000 else f'WEAK: PBKDF2 {it} iters (<600k, OWASP 2023+)'
    if scheme in ('argon2id', 'scrypt'):
        return 'STRONG: memory-hard KDF'
    return 'UNKNOWN scheme'
```

---

## 4. Detection

- **Offline cracking** generates **zero target telemetry** — defensive value is in the
  *finding*: flag fast-hash password storage, low bcrypt cost, low PBKDF2 iteration counts.
- If cracking pivots to **online** spraying it becomes T1110.001 — detectable as auth
  failures; Sigma on failed-logon bursts per source.
- **PQ / HNDL** defensive detection: inventory long-lived-confidential data still protected
  by classical-only TLS; alert on negotiated groups lacking an ML-KEM hybrid for sensitive
  services.

```yaml
title: Weak Password Storage / Non-PQ TLS for Sensitive Data
id: kdf-pq-hygiene
logsource: { product: appsec_scan }
detection:
  weak_kdf: { hash_scheme: ['md5','sha1','sha256','ntlm'], context: 'password' }
  weak_bcrypt: { hash_scheme: 'bcrypt', cost: '< 12' }
  classical_tls: { negotiated_group: ['x25519','secp256r1'], data_class: 'long_lived_secret' }
  condition: weak_kdf or weak_bcrypt or classical_tls
level: medium
```

---

## 5. OPSEC

- Cracking is offline and silent; the OPSEC concern is **loot handling** — encrypt cracked
  credential lists at rest, restrict to the engagement vault, purge on close-out.
- Never spray recovered creds against live auth without explicit ROE (that is a separate,
  noisy, in-scope-only action).
- PQ assessment is passive measurement of negotiated parameters — no footprint.

---

## 6. References
- hashcat RTX 4090 v6.2.6 benchmarks — gist.github.com/Chick3nman
- GPU cracking benchmarks 2025/26 — onlinehashcrack.com, tutorials.technology
- bcrypt vs RTX 5090 — specopssoft.com/blog/bcrypt-is-new-gen-hardware-and-ai-making-password-hacking-faster/
- NIST FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA), Aug 2024
- NIST IR 8547 — Transition to Post-Quantum Cryptography Standards
- CSA — "AI Infrastructure, Post-Quantum, Harvest Now Decrypt Later"
- OWASP Password Storage Cheat Sheet (KDF iteration baselines)
