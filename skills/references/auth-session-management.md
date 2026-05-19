---
title: Secure Session Management — Strong Tokens, Proper Attributes, and Lifecycle Control
impact: HIGH
impactDescription: Weak session management enables session hijacking and fixation attacks
tags: session, cookies, token, fixation, hijacking, entropy, httponly, samesite
---

## Secure Session Management — Strong Tokens, Proper Attributes, and Lifecycle Control

Session vulnerabilities include weak token generation (predictable PRNG, insufficient entropy), missing cookie security attributes, session fixation (token not regenerated after login), and failure to invalidate sessions on password change or logout.

**Incorrect (weak token, missing attributes, no regeneration):**

```python
import random
import string

# Weak token: predictable PRNG, insufficient entropy
def create_session(user_id: int) -> str:
    token = "".join(random.choices(string.ascii_letters, k=16))  # math PRNG!
    sessions[token] = {"user_id": user_id}
    return token

@app.route("/login", methods=["POST"])
def login():
    user = authenticate(request.form["username"], request.form["password"])
    if user:
        token = create_session(user.id)
        resp = make_response(redirect("/dashboard"))
        resp.set_cookie("session", token)  # Missing Secure, HttpOnly, SameSite
        return resp

# Session fixation: token from before login is reused after login
# No invalidation on password change or logout
@app.route("/logout")
def logout():
    return redirect("/")  # Session token still valid!
```

**Correct (cryptographic tokens, secure attributes, proper lifecycle):**

```python
import secrets

# Strong token: cryptographic PRNG, 256 bits of entropy
def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)  # 256 bits from os.urandom
    sessions[token] = {
        "user_id": user_id,
        "created_at": time.time(),
        "expires_at": time.time() + 3600,  # 1 hour timeout
    }
    return token

@app.route("/login", methods=["POST"])
def login():
    user = authenticate(request.form["username"], request.form["password"])
    if user:
        # Invalidate any pre-existing session (prevents fixation)
        old_token = request.cookies.get("session")
        if old_token:
            sessions.pop(old_token, None)

        token = create_session(user.id)
        resp = make_response(redirect("/dashboard"))
        resp.set_cookie(
            "session", token,
            httponly=True,     # Not accessible via JavaScript
            secure=True,       # HTTPS only
            samesite="Lax",    # CSRF protection
            max_age=3600,      # Browser-side expiration
        )
        return resp

@app.route("/logout")
def logout():
    token = request.cookies.get("session")
    if token:
        sessions.pop(token, None)  # Server-side invalidation
    resp = make_response(redirect("/"))
    resp.delete_cookie("session")
    return resp
```

Regenerate session tokens after any privilege level change (login, role change, MFA completion). Invalidate all sessions on password change. Never expose session tokens in URLs (leaked via referrer headers and browser history). Enforce concurrent session limits for sensitive applications.
