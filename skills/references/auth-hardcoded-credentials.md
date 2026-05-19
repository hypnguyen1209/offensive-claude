---
title: Eliminate Hard-coded Credentials — Use Secret Management for All Credentials
impact: CRITICAL
impactDescription: Hard-coded credentials enable full system compromise once source code or binaries are analyzed
tags: hardcoded-credentials, secrets, api-keys, default-passwords, cwe-798
---

## Eliminate Hard-coded Credentials — Use Secret Management for All Credentials

Hard-coded credentials (CWE-798) embed passwords, API keys, tokens, or cryptographic keys directly in source code, configuration files, or compiled binaries. Attackers extract them through source code access, binary decompilation, or public repository scanning. 41 high-severity CVEs in the last 6 months (avg CVSS 8.7), including CVE-2025-14611 (Gladinet hardcoded AES key, CVSS 9.8) and CVE-2026-22769 (Dell RecoverPoint hardcoded creds, CVSS 10).

**Incorrect (credentials embedded in source and config):**

```python
# Hard-coded database password
DB_PASSWORD = "SuperSecret123!"
db = connect(host="db.internal", password=DB_PASSWORD)

# API key in source
STRIPE_KEY = "sk_live_EXAMPLE_DO_NOT_USE_xxxxxxxx"
stripe.api_key = STRIPE_KEY

# Hard-coded JWT secret
JWT_SECRET = "my-jwt-secret-key-2024"
token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

# SSH key embedded in Docker image
COPY id_rsa /root/.ssh/id_rsa
```

**Correct (load credentials from secret management at runtime):**

```python
import os
from functools import lru_cache

# Option 1: Environment variables (minimum viable approach)
db = connect(host="db.internal", password=os.environ["DB_PASSWORD"])

# Option 2: Secret manager (production)
from cloud_provider import SecretManager

@lru_cache(maxsize=1)
def get_secret(name: str) -> str:
    client = SecretManager()
    return client.get_secret_value(SecretId=name)["SecretString"]

stripe.api_key = get_secret("stripe-api-key")
token = jwt.encode(payload, get_secret("jwt-signing-key"), algorithm="HS256")

# Option 3: Vault with lease-based rotation
import hvac
vault = hvac.Client(url=os.environ["VAULT_ADDR"])
creds = vault.secrets.database.generate_credentials("my-role")
db = connect(host="db.internal", user=creds["username"], password=creds["password"])
```

Scan repositories with tools like `gitleaks`, `trufflehog`, or GitHub secret scanning. Use pre-commit hooks to block credential commits. Rotate any credential that was ever committed to version control — history persists even after deletion. For shared SSH keys, use certificate-based authentication with short-lived certificates instead.
