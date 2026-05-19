---
title: Enforce TLS Certificate Validation — Never Disable Hostname or Chain Verification
impact: HIGH
impactDescription: Disabled certificate validation enables man-in-the-middle attacks that intercept all encrypted traffic
tags: tls, certificate-validation, hostname-verification, mitm, cwe-295
---

## Enforce TLS Certificate Validation — Never Disable Hostname or Chain Verification

Improper certificate validation (CWE-295) occurs when applications disable TLS certificate chain verification, hostname checking, or certificate pinning. This enables man-in-the-middle attacks where an attacker with network position intercepts all traffic despite HTTPS. 17 high-severity CVEs in the last 6 months (avg CVSS 8.1), including CVE-2025-68121 (Go crypto/tls session resumption bypass, CVSS 10) and CVE-2026-25961 (SumatraPDF disabled hostname verification).

**Incorrect (disabling certificate verification):**

```python
import requests
import urllib3

# Disabling verification entirely
urllib3.disable_warnings()
response = requests.get("https://api.example.com", verify=False)  # MitM vulnerable

# Custom SSL context that accepts anything
import ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE  # Accepts self-signed, expired, wrong-host certs
```

```go
// Go: Disabling certificate verification
client := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: true,  // Accepts any certificate
        },
    },
}
```

**Correct (enforce verification, use proper CA bundles):**

```python
import requests
import certifi

# Use system CA bundle or certifi (default in requests)
response = requests.get("https://api.example.com")  # verify=True is default

# For internal CAs, specify the CA bundle explicitly
response = requests.get("https://internal.corp.com", verify="/etc/ssl/internal-ca.pem")

# For certificate pinning (high-security scenarios)
from requests_toolbelt.adapters.fingerprint import FingerprintAdapter
session = requests.Session()
session.mount("https://api.example.com", FingerprintAdapter("sha256_digest_here"))
```

```go
// Go: Use proper CA configuration
pool := x509.NewCertPool()
pool.AppendCertsFromPEM(internalCACert)
client := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{
            RootCAs:    pool,  // Custom CA if needed, but always verify
            MinVersion: tls.VersionTLS12,
        },
    },
}
```

Search the codebase for `verify=False`, `InsecureSkipVerify`, `CERT_NONE`, `checkServerIdentity: () => undefined`, and `rejectUnauthorized: false`. Every instance is a MitM vulnerability. For internal services with private CAs, configure the CA bundle — don't disable verification. `verify=False` in test code should use a test CA certificate, not disabled validation.
