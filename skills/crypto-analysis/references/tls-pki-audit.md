# TLS / SSL / SSH & PKI Auditing

Cluster covering transport-crypto posture: negotiation/downgrade flaws, RSA decryption
oracles, legacy protocol attacks, and X.509 / Certificate-Transparency analysis.
ATT&CK: T1600.001 (Downgrade System Image / crypto downgrade analog), T1557 (AiTM),
T1040 (Network Sniffing). CWE-326 (Inadequate Encryption Strength), CWE-295 (Improper
Certificate Validation), CWE-208 (Observable Timing Discrepancy), CWE-222 (truncated msg).

---

## 1. Theory / mechanism

A TLS/SSH endpoint negotiates a *cipher suite* (key exchange + auth + bulk cipher + MAC)
and a *protocol version*. Attacks live at three layers:

- **Negotiation/downgrade** — coerce peers into the weakest mutually-supported option
  (export DH, 64-bit block ciphers, RSA key transport, SSLv3) then break that.
- **Implementation oracles** — error/timing differences during RSA decryption (PKCS#1
  v1.5) leak plaintext bit-by-bit (Bleichenbacher / Marvin / ROBOT).
- **Protocol integrity gaps** — message injection/truncation before the channel is fully
  authenticated (Terrapin in SSH).

PKI auditing inspects the X.509 chain (key size, signature algorithm, validity, SAN,
constraints, revocation) and mines public Certificate-Transparency logs for forgotten or
internal assets.

---

## 2. Modern 2024-2026 variants (verified)

| Name | ID | What it is | Status |
|------|-----|-----------|--------|
| Terrapin | CVE-2023-48795 | SSH prefix-truncation against `chacha20-poly1305@openssh.com` and `*-etm@openssh.com`; strips `SSH_MSG_EXT_INFO` → ext-negotiation downgrade. ChaCha20-Poly1305 path is deterministic (works every connection); CBC-EtM path is probabilistic. | Mitigated by **strict kex** (`kex-strict-c/s-v00@openssh.com`); still ubiquitous on un-patched gear. |
| Marvin Attack | CVE-2022-4304 (OpenSSL), CVE-2023-46809 (Node), CVE-2024-2236 (libgcrypt) | Timing variant of Bleichenbacher; affects **all** RSA padding (PKCS#1v1.5, OAEP, RSASVE). Recovers plaintext / forges signatures via timing of RSA decrypt. | Mitigation = implicit rejection (constant-time) + move to OAEP / drop RSA key transport. |
| OpenSSL 2025 batch | CVE-2025-9230/9231/9232 | 9231 = SM2 signature timing side-channel on 64-bit ARM (custom providers only); 9230 = CMS PWRI OOB R/W. Not classic Bleichenbacher but timing-relevant. | Fixed in 3.5.4/3.4.3/3.3.5/3.2.6/3.0.18/1.1.1zd/1.0.2zm. |
| Legacy still-live | SWEET32, DROWN, Logjam, POODLE, ROBOT | 64-bit block birthday (3DES/Blowfish), SSLv2 cross-protocol RSA, export-DH precompute, SSLv3 CBC, RSA PKCS#1 oracle. | Found constantly on internal/IoT/appliance estates. |

Sources: terrapin-attack.com / CVE-2023-48795 advisory (GHSA-45x7-px36-x8w8);
people.redhat.com/~hkario/marvin/ (Marvin); openssl-library.org/news/vulnerabilities/
(2025 CVEs); securityaffairs CVE-2025-9230/9231/9232 coverage.

---

## 3. Complete working commands

### Canonical posture sweep
```bash
# testssl.sh — the reference scanner. Pin a JSON for the report artifact.
testssl.sh --full --robot --sweet32 --drown --logjam --poodle \
  --jsonfile=tls_report.json https://target.com
# Specific checks
testssl.sh --starttls smtp target.com:25       # opportunistic TLS on mail/db/ldap
testssl.sh -E target.com                        # enumerate every offered cipher
```

### OpenSSL manual probes
```bash
# Protocol/version support matrix
for v in ssl3 tls1 tls1_1 tls1_2 tls1_3; do
  echo -n "$v: "; echo | openssl s_client -connect t:443 -$v 2>/dev/null | grep -q 'CONNECTED' && echo UP || echo down
done
# Weak/null ciphers explicitly
openssl s_client -connect t:443 -cipher 'NULL:eNULL:aNULL:EXPORT:DES:3DES:RC4'
# Full cert + chain
echo | openssl s_client -connect t:443 -showcerts 2>/dev/null | \
  openssl x509 -noout -text -fingerprint -sha256
```

### Terrapin detection
```bash
# Check whether SSH offers a vulnerable cipher AND lacks strict-kex.
ssh -vv -o KexAlgorithms=+diffie-hellman-group14-sha1 target -p 22 2>&1 | grep -E 'kex|cipher|mac'
# Authoritative scanner (Terrapin team):
#   go install github.com/RUB-NDS/Terrapin-Scanner@latest
#   Terrapin-Scanner --connect target:22
# Vulnerable iff (chacha20-poly1305@openssh.com OR *-etm@openssh.com CBC) AND no kex-strict.
```
Our `scripts/tls_audit.py` performs all of the above (protocol matrix, weak-cipher flags,
SWEET32/3DES presence, cert grading, SSH algorithm + strict-kex check) and emits a JSON
finding record. testssl.sh remains the cross-check oracle.

### Certificate-Transparency shadow-asset discovery (passive)
```bash
# crt.sh JSON — find staging/internal subdomains, forgotten certs
curl -s "https://crt.sh/?q=%25.target.com&output=json" | \
  jq -r '.[].name_value' | tr ',' '\n' | sed 's/\*\.//' | sort -u
# Cross-reference issuance dates for short-lived / mis-issued certs.
```

---

## 4. Detection

```yaml
title: Bleichenbacher/Marvin RSA Oracle Probing
id: 6f2c1d3a-tls-marvin
logsource: { category: network_connection, product: zeek }
detection:
  sel_decrypt_errors:
    service: 'ssl'
    # repeated TLS RSA-key-exchange handshakes that fail at Finished, same src
    history|contains: 'alert'
  threshold: { ssl.cipher|contains: 'RSA', count: '> 1000 within 5m per src_ip' }
  condition: sel_decrypt_errors and threshold
level: high
```

- **Terrapin (server side):** OpenSSH logs `kex` mismatch / unexpected message ordering;
  a NIDS sees `SSH_MSG_IGNORE` injected pre-NEWKEYS and a sequence-number jump. IOC:
  on-path device, client and server disagree on `kex-strict` flag.
- **TLS scanning:** Zeek `ssl.log` showing one source offering huge cipher lists and many
  short-lived handshakes; spike of `tls_alert` records.
- **EDR/host:** for Marvin, the *victim app* shows abnormal RSA-decrypt call volume from a
  single peer — instrument with eBPF on `EVP_PKEY_decrypt`.

---

## 5. OPSEC

- Cert/CT recon is **fully passive** (crt.sh, censys, ct logs) — no target-side trace; do
  this first.
- Active TLS enumeration is loud: rate-limit, randomize source, and never run the full
  `testssl --vulnerable` battery against production without explicit ROE — ROBOT/Marvin
  probing alone is 10^4–10^6 decrypts.
- Terrapin requires an **active MitM** position; abort if the peer advertises
  `kex-strict-*` (you cannot strip EXT_INFO and the injection is detectable).
- Cleanup: scanning leaves no artifacts on target beyond logs you cannot remove; document
  scan windows in the engagement log so blue team can correlate.

---

## 6. References
- Terrapin: https://terrapin-attack.com/ ; CVE-2023-48795 (GHSA-45x7-px36-x8w8)
- Marvin Attack: https://people.redhat.com/~hkario/marvin/ ; CVE-2022-4304, CVE-2024-2236
- OpenSSL 2025 advisories: https://openssl-library.org/news/vulnerabilities/ (CVE-2025-9230/9231/9232)
- Bleichenbacher (1998) / ROBOT (2018, robotattack.org)
- crt.sh Certificate Transparency search
