---
title: Use Modern Cryptographic Algorithms — Never MD5, SHA1, DES, or RC4 for Security
impact: HIGH
impactDescription: Weak cryptography enables password cracking, forgery, and data decryption
tags: cryptography, hashing, encryption, bcrypt, argon2, aes-gcm, weak-algorithms
---

## Use Modern Cryptographic Algorithms — Never MD5, SHA1, DES, or RC4 for Security

Weak algorithms provide false security: MD5 and SHA1 are broken for collision resistance, DES and RC4 are trivially crackable, ECB mode reveals plaintext patterns, and CBC without authentication enables padding oracle attacks. Password hashing requires purpose-built KDFs (bcrypt, Argon2), not raw hash functions.

**Incorrect (weak algorithms for security-critical operations):**

```python
import hashlib
from Crypto.Cipher import AES, DES

# Weak password hashing: MD5 is fast to brute-force, no salt
def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()  # Cracked in seconds

# Weak encryption: DES with ECB mode reveals patterns
def encrypt_data(key: bytes, data: bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_ECB)  # ECB: identical blocks = identical ciphertext
    return cipher.encrypt(pad(data, 8))

# AES-CBC without authentication: vulnerable to padding oracle
def encrypt_message(key: bytes, data: bytes) -> bytes:
    iv = b"\x00" * 16  # Static IV: identical plaintexts produce identical ciphertexts
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(data, 16))  # No integrity check
```

**Correct (modern algorithms with proper parameters):**

```python
import bcrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# Strong password hashing: bcrypt with automatic salt, tunable work factor
def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

def verify_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), hashed)

# Authenticated encryption: AES-256-GCM provides confidentiality + integrity
def encrypt_data(key: bytes, data: bytes) -> bytes:
    nonce = os.urandom(12)  # Unique nonce for every encryption
    aesgcm = AESGCM(key)   # 256-bit key
    ciphertext = aesgcm.encrypt(nonce, data, None)  # Includes auth tag
    return nonce + ciphertext

def decrypt_data(key: bytes, token: bytes) -> bytes:
    nonce, ciphertext = token[:12], token[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)  # Verifies integrity
```

AES-GCM nonce reuse is catastrophic — it reveals the authentication key. ECDSA nonce reuse leaks the private key. RSA without OAEP padding is vulnerable to Bleichenbacher attacks. Always use constant-time comparison for cryptographic values (`hmac.compare_digest()`, not `==`).
