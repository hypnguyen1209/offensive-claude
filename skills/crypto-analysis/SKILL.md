---
name: crypto-analysis
description: Cryptographic assessment — TLS/PKI auditing, RSA/ECC key attacks, ECDSA nonce lattice recovery, symmetric/AEAD misuse, JWT/JOSE forgery, hash cracking, and post-quantum migration review
metadata:
  type: offensive
  phase: analysis
  tools: testssl.sh, openssl, hashcat, john, RsaCtfTool, sagemath, jwt_tool, ecdsa-lattice
  mitre: [T1600, T1600.001, T1557, T1110.002, T1552.004, T1606.001, T1040]
kill_chain:
  phase: [recon, exploit]
  step: [1, 4]
  attck_tactics: [TA0043, TA0006, TA0009]
  attck_techniques: [T1600, T1600.001, T1557, T1557.001, T1110.002, T1552.004, T1606.001, T1040]
depends_on: [recon-osint]
feeds_into: [exploit-development, web-pentest, network-attack]
inputs: [tls_config, crypto_implementation, hash_samples, public_keys, jwt_tokens, signature_corpus]
outputs: [crypto_weakness_report, finding_record, recovered_keys, cracked_credentials]
references:
  - references/tls-pki-audit.md
  - references/rsa-attacks.md
  - references/ecc-nonce-attacks.md
  - references/symmetric-aead.md
  - references/jwt-jose.md
  - references/hash-pq.md
scripts:
  - scripts/tls_audit.py
  - scripts/rsa_attack.py
  - scripts/ecdsa_lattice.py
  - scripts/padding_oracle.py
  - scripts/gcm_nonce_reuse.py
  - scripts/jwt_forge.py
  - scripts/hash_triage.py
---

# Cryptographic Analysis

## When to Activate

- Auditing TLS/SSL/SSH configurations and X.509 PKI (cipher suites, downgrade, protocol flaws)
- Reviewing crypto implementations in source code or captured traffic
- Attacking weak RSA/ECC keys (CTF and real-world weak-key hygiene)
- Recovering ECDSA/DSA private keys from reused or biased nonces (lattice/HNP)
- Exploiting symmetric/AEAD misuse: padding oracles, GCM nonce reuse, key-commitment
- Forging JWT/JOSE tokens (algorithm confusion, none, jwk/jku/kid injection)
- Cracking password hashes and grading KDF strength
- Assessing post-quantum readiness ("harvest now, decrypt later" exposure)

## Technique Map

| Technique | ATT&CK | CWE | Reference | Script |
|-----------|--------|-----|-----------|--------|
| TLS cipher/protocol downgrade audit | T1600.001 | CWE-326 | references/tls-pki-audit.md | scripts/tls_audit.py |
| Terrapin SSH prefix truncation (CVE-2023-48795) | T1557 | CWE-222 | references/tls-pki-audit.md | scripts/tls_audit.py |
| Marvin/Bleichenbacher RSA timing oracle | T1600 | CWE-208 | references/tls-pki-audit.md | scripts/tls_audit.py |
| X.509 / CT-log shadow-asset discovery | T1589 | CWE-295 | references/tls-pki-audit.md | scripts/tls_audit.py |
| RSA weak-key factoring (Fermat/Wiener/common-modulus) | T1600 | CWE-326 | references/rsa-attacks.md | scripts/rsa_attack.py |
| Coppersmith partial-key & ROCA (CVE-2017-15361) | T1600 | CWE-310 | references/rsa-attacks.md | scripts/rsa_attack.py |
| Hastad broadcast / batch-GCD | T1600 | CWE-326 | references/rsa-attacks.md | scripts/rsa_attack.py |
| ECDSA nonce reuse key recovery | T1552.004 | CWE-323 | references/ecc-nonce-attacks.md | scripts/ecdsa_lattice.py |
| Biased-nonce lattice/HNP (Minerva, PuTTY CVE-2024-31497) | T1552.004 | CWE-1241 | references/ecc-nonce-attacks.md | scripts/ecdsa_lattice.py |
| Psychic signature (0,0) (CVE-2022-21449) | T1606.001 | CWE-347 | references/ecc-nonce-attacks.md | scripts/ecdsa_lattice.py |
| CBC padding oracle (byte-by-byte decrypt) | T1040 | CWE-209 | references/symmetric-aead.md | scripts/padding_oracle.py |
| AES-GCM nonce reuse "forbidden attack" | T1040 | CWE-323 | references/symmetric-aead.md | scripts/gcm_nonce_reuse.py |
| AEAD key-commitment / invisible salamanders / partitioning oracle | T1606 | CWE-347 | references/symmetric-aead.md | scripts/gcm_nonce_reuse.py |
| JWT algorithm confusion RS256→HS256 (CVE-2024-54150) | T1606.001 | CWE-347 | references/jwt-jose.md | scripts/jwt_forge.py |
| JWT alg=none / jwk / jku / kid injection | T1606.001 | CWE-347 | references/jwt-jose.md | scripts/jwt_forge.py |
| Hash identification & GPU cracking | T1110.002 | CWE-916 | references/hash-pq.md | scripts/hash_triage.py |
| Weak KDF / fast-hash password storage | T1110.002 | CWE-916 | references/hash-pq.md | scripts/hash_triage.py |
| Post-quantum / HNDL exposure review | T1600 | CWE-327 | references/hash-pq.md | scripts/tls_audit.py |

## Quick Start

```bash
# 0. TLS/PKI posture in one shot (downgrade, ROBOT, SWEET32, Terrapin, cert/CT)
python3 scripts/tls_audit.py target.com:443 --ssh target.com:22 --ct --json out.json
testssl.sh --full --robot --sweet32 https://target.com   # cross-check with the canonical tool

# 1. RSA weak-key triage on a captured public key
python3 scripts/rsa_attack.py --pubkey server.pem --ct ciphertext.b64 --auto
#   tries Fermat (p~=q), Wiener (small d), batch-GCD/common-modulus, ROCA fingerprint

# 2. ECDSA key recovery from a signature corpus (reuse or bias)
python3 scripts/ecdsa_lattice.py recover sigs.json --curve secp256r1 --known-msb 4
#   reuse: needs 2 sigs w/ same r; bias: ~256-1200 sigs depending on leak

# 3. Symmetric/AEAD misuse
python3 scripts/padding_oracle.py --url https://t/dec --ct $CT --block 16   # CBC oracle
python3 scripts/gcm_nonce_reuse.py forbidden ct1.bin ct2.bin --nonce $N     # recover H + forge

# 4. JWT forgery chain
python3 scripts/jwt_forge.py confusion --pubkey jwt_pub.pem --claims '{"role":"admin"}'
python3 scripts/jwt_forge.py none      --claims '{"sub":"admin"}'

# 5. Hash triage + crack plan
python3 scripts/hash_triage.py hashes.txt            # identify + emit hashcat -m / john format
hashcat -m 22000 capture.hc22000 wl.txt -r rules/best64.rule
```

## OPSEC & Detection (summary)

| Technique | Telemetry / IOC | Detection (Sigma/EDR) | OPSEC note |
|-----------|-----------------|-----------------------|------------|
| TLS scanning / testssl | Burst of handshakes, many cipher renegotiations, malformed ClientHellos | NIDS: high TLS alert rate from one src; Zeek `ssl.log` anomalous cipher offers | Rate-limit, spread across source IPs; passive cert/CT recon leaves no target-side trace |
| Marvin/ROBOT oracle probing | ~10^4–10^6 RSA decrypts, repeated malformed pre-master/CMS | WAF/IDS: spike of TLS decrypt errors, identical-size payloads | Extremely loud; only against authorized hosts; use minimal query budgets |
| Terrapin MitM | Injected SSH_MSG_IGNORE, sequence-number gap at NEWKEYS | SSH server logs `kex` mismatch; netflow showing on-path device | Requires active MitM; detectable by strict-kex peers; abort if `kex-strict` present |
| ECDSA nonce harvesting | Bulk signature collection (Git, TLS, SSH, blockchain) | Mostly offline — no target telemetry once sigs captured | Collection is passive; recovery is offline; rotate-key advice in report |
| CBC padding oracle | Thousands of decrypt requests, alternating valid/invalid padding | Web logs: ~256×blocks requests to one endpoint; Sigma on 4xx burst | Very noisy (256×blocks×msgs); throttle, randomize timing |
| GCM nonce reuse / partitioning | Repeated (nonce,key) pairs; multi-key ciphertext blobs | App crypto audit; flag reused IVs in logs | Forbidden-attack math is offline once two ciphertexts captured |
| JWT forgery | Anomalous `alg`, external `jku`/`x5u` fetch, all-zero ES signature | Sigma: JWT with `alg:none`/HS after RS expected; egress to attacker JWKS URL | Each forged token is a single request; minimal noise |
| Hash cracking | None on target (offline) | N/A unless online spray (then T1110) | Offline; protect loot at rest; never spray live without scope |

## Deep Dives

- **references/tls-pki-audit.md** — TLS/SSL/SSH posture: cipher/protocol downgrade, Terrapin (CVE-2023-48795), Marvin/Bleichenbacher (CVE-2022-4304, CVE-2024-2236), SWEET32/DROWN/Logjam/POODLE, X.509 and Certificate-Transparency analysis.
- **references/rsa-attacks.md** — Weak-key factoring: Fermat, Wiener, common modulus, Hastad broadcast, Coppersmith partial-key, batch-GCD, ROCA (CVE-2017-15361); RsaCtfTool / cado-nfs / SageMath workflow.
- **references/ecc-nonce-attacks.md** — ECDSA/DSA nonce reuse, biased-nonce lattice/HNP recovery (Minerva, PuTTY CVE-2024-31497), invalid-curve attacks, psychic signatures (CVE-2022-21449).
- **references/symmetric-aead.md** — Block-cipher mode misuse: ECB detection, CBC padding oracle, CTR/GCM nonce reuse (forbidden attack), AEAD key-commitment / invisible salamanders / partitioning oracles.
- **references/jwt-jose.md** — JWT/JOSE token forgery: algorithm confusion (CVE-2024-54150), alg=none, jwk/jku/x5u/kid injection, weak-secret cracking, library-level CVE landscape.
- **references/hash-pq.md** — Hash identification, modern GPU cracking economics (RTX 40/50-series), KDF strength grading, and post-quantum migration / "harvest now, decrypt later" assessment (ML-KEM/ML-DSA, hybrid TLS, crypto-agility).
