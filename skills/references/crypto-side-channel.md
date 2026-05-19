---
title: Prevent Side-Channel Leaks — Use Constant-Time Operations for Secret-Dependent Logic
impact: HIGH
impactDescription: Timing and observable differences leak secret keys, passwords, and tokens through measurable variations in execution
tags: side-channel, timing-attack, constant-time, observable-discrepancy, cwe-203
---

## Prevent Side-Channel Leaks — Use Constant-Time Operations for Secret-Dependent Logic

Observable discrepancy (CWE-203) occurs when an application's behavior differs measurably depending on secret values — through execution timing, error messages, cache access patterns, or power consumption. Timing attacks on string comparison can extract API keys byte-by-byte. Username enumeration via different error messages or response times reveals valid accounts. 5 high-severity CVEs in the last 6 months (avg CVSS 8.4), including CVE-2026-23519 (RustCrypto CMOV constant-time bypass, CVSS 9.8).

**Incorrect (secret-dependent timing and observable differences):**

```python
# Early-exit string comparison leaks token length and prefix
def verify_api_key(provided, stored):
    if len(provided) != len(stored):
        return False  # Length oracle — attacker learns exact key length
    for a, b in zip(provided, stored):
        if a != b:
            return False  # Timing oracle — fails faster on wrong first byte
    return True

# Username enumeration via different error messages
@app.route('/login', methods=['POST'])
def login():
    user = User.query.filter_by(email=request.json['email']).first()
    if not user:
        return jsonify({"error": "User not found"}), 401  # Reveals valid emails
    if not user.check_password(request.json['password']):
        return jsonify({"error": "Wrong password"}), 401   # Different message
    return jsonify({"token": create_token(user)})
```

```go
// Timing-vulnerable HMAC comparison
func verifySignature(message, signature, key []byte) bool {
    expected := computeHMAC(message, key)
    // bytes.Equal returns early on first difference — timing oracle
    return bytes.Equal(expected, signature)
}
```

**Correct (constant-time operations and uniform responses):**

```python
import hmac
import hashlib

# Constant-time comparison — always compares all bytes
def verify_api_key(provided, stored):
    return hmac.compare_digest(provided.encode(), stored.encode())

# Uniform error messages and timing for authentication
@app.route('/login', methods=['POST'])
def login():
    user = User.query.filter_by(email=request.json['email']).first()

    # Always hash the password even if user doesn't exist — prevents timing oracle
    dummy_hash = "$2b$12$LJ3m4ys3Lk0TDbGMOYBk6O"  # Pre-computed bcrypt hash
    password = request.json['password']

    if user:
        valid = user.check_password(password)
    else:
        # Spend the same time hashing against dummy to prevent user enumeration
        import bcrypt
        bcrypt.checkpw(password.encode(), dummy_hash.encode())
        valid = False

    if not valid:
        return jsonify({"error": "Invalid credentials"}), 401  # Same message always
    return jsonify({"token": create_token(user)})
```

```go
import "crypto/subtle"

// Constant-time HMAC comparison
func verifySignature(message, signature, key []byte) bool {
    expected := computeHMAC(message, key)
    // subtle.ConstantTimeCompare doesn't short-circuit
    return subtle.ConstantTimeCompare(expected, signature) == 1
}
```

Use `hmac.compare_digest()` (Python), `crypto/subtle.ConstantTimeCompare` (Go), `crypto.timingSafeEqual` (Node.js), or `constant_time_compare` (Ruby) for all secret comparisons. Return identical error messages and HTTP status codes for authentication failures regardless of whether the account exists. For cryptographic code, audit compiler output to ensure constant-time source isn't optimized into branching — use libraries like `subtle` crates in Rust rather than hand-rolling.
