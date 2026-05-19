---
title: Protect Cryptographic Keys and Secrets — Never Hardcode, Always Rotate
impact: HIGH
impactDescription: Exposed secrets enable complete system compromise and persist in version control history
tags: secrets, api-keys, hardcoded-credentials, key-management, entropy, prng
---

## Protect Cryptographic Keys and Secrets — Never Hardcode, Always Rotate

Hardcoded secrets in source code, configuration defaults, or environment variable fallbacks are the most common cryptographic vulnerability. Secrets committed to version control persist in history even after removal. Insufficient entropy from non-cryptographic PRNGs (math.random, rand()) produces predictable tokens.

**Incorrect (hardcoded secrets and weak random generation):**

```python
import random
import jwt

# Hardcoded secret: visible in source code and version control
SECRET_KEY = "super-secret-key-123"
DB_PASSWORD = "admin123"

# Weak PRNG: math random is predictable, not cryptographic
def generate_api_key() -> str:
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choice(chars) for _ in range(32))  # Predictable!

# Secret in environment with insecure default
SECRET = os.environ.get("JWT_SECRET", "default-dev-secret")

# Secret logged in plaintext
def authenticate(token: str):
    try:
        return jwt.decode(token, SECRET_KEY)
    except jwt.DecodeError as e:
        logger.error(f"JWT decode failed with key {SECRET_KEY}: {e}")  # Key leaked!
```

**Correct (external secret management and cryptographic randomness):**

```python
import secrets
import os
import jwt

# Secrets from environment — fail if not set (no insecure defaults)
SECRET_KEY = os.environ["JWT_SECRET"]  # KeyError if missing = safe failure
DB_PASSWORD = os.environ["DB_PASSWORD"]

# Cryptographic PRNG: os.urandom / secrets module
def generate_api_key() -> str:
    return secrets.token_urlsafe(32)  # 256 bits from os.urandom

# Validate required secrets at startup
def validate_config():
    required = ["JWT_SECRET", "DB_PASSWORD", "ENCRYPTION_KEY"]
    missing = [key for key in required if not os.environ.get(key)]
    if missing:
        raise RuntimeError(f"Missing required secrets: {missing}")

# Never log secret material
def authenticate(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.DecodeError:
        logger.warning("JWT decode failed for request")  # No secret in log
        return None
```

Use `os.urandom()`, `secrets` module (Python), `crypto.getRandomValues()` (JS), or `/dev/urandom` for all security-sensitive random values. Store secrets in vaults (HashiCorp Vault, AWS Secrets Manager), not environment variables on shared systems. Zeroize key material from memory after use. Never log or include secrets in error messages or stack traces.
