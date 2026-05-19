---
title: Harden API Endpoints — Prevent Mass Assignment, Excessive Exposure, and Abuse
impact: MEDIUM-HIGH
impactDescription: API vulnerabilities expose sensitive data and enable unauthorized operations at scale
tags: api-security, mass-assignment, data-exposure, rate-limiting, graphql, bola
---

## Harden API Endpoints — Prevent Mass Assignment, Excessive Exposure, and Abuse

API security failures include returning full database objects instead of DTOs (leaking internal fields), accepting unexpected fields in request bodies (mass assignment), missing rate limiting, and GraphQL-specific issues like unbounded query depth and disabled field-level authorization.

**Incorrect (excessive data exposure, no rate limiting, unsafe GraphQL):**

```python
# Excessive exposure: returns full user object including internal fields
@app.route("/api/users/<int:user_id>")
def get_user(user_id):
    user = db.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return jsonify(dict(user))  # Leaks: password_hash, internal_notes, role, mfa_secret

# No rate limiting: brute force and enumeration attacks possible
@app.route("/api/login", methods=["POST"])
def login():
    user = authenticate(request.json["email"], request.json["password"])
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401
    # Attacker can try millions of passwords without throttling

# GraphQL: unbounded depth allows DoS
# query { user { friends { friends { friends { ... } } } } }
schema = graphene.Schema(query=Query)  # No depth limit, no complexity analysis
```

**Correct (DTOs, rate limiting, bounded GraphQL):**

```python
from dataclasses import dataclass
from functools import wraps
import time

# DTO: explicitly define what fields are returned
@dataclass
class UserResponse:
    id: int
    name: str
    email: str
    created_at: str

@app.route("/api/users/<int:user_id>")
@require_auth
def get_user(user_id):
    user = db.execute("SELECT id, name, email, created_at FROM users WHERE id = %s", (user_id,))
    if not user:
        abort(404)
    return jsonify(UserResponse(**user).__dict__)

# Rate limiting: per-IP and per-account throttling
def rate_limit(max_requests: int, window_seconds: int):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            key = f"rate:{request.remote_addr}:{f.__name__}"
            current = redis.incr(key)
            if current == 1:
                redis.expire(key, window_seconds)
            if current > max_requests:
                abort(429, "Rate limit exceeded")
            return f(*args, **kwargs)
        return decorated
    return decorator

@app.route("/api/login", methods=["POST"])
@rate_limit(max_requests=5, window_seconds=60)
def login():
    user = authenticate(request.json["email"], request.json["password"])
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401
    return jsonify({"token": create_token(user)})
```

For GraphQL: set maximum query depth (typically 7-10), limit query complexity scoring, disable introspection in production, and enforce field-level authorization in resolvers (not just at the query root). Old API versions with known vulnerabilities should be decommissioned, not just deprecated.
