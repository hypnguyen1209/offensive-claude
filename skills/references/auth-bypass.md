---
title: Enforce Authentication on Every Sensitive Endpoint — Default to Deny
impact: HIGH
impactDescription: Authentication bypass gives attackers full access to protected functionality and data
tags: authentication, bypass, jwt, oauth, session, middleware, default-deny
---

## Enforce Authentication on Every Sensitive Endpoint — Default to Deny

Authentication bypass occurs when sensitive endpoints lack authentication checks, when JWT validation is insufficient, when middleware ordering allows bypass, or when route matching differences create gaps. Default-deny means every route requires authentication unless explicitly marked as public — never the reverse.

**Incorrect (missing auth, JWT algorithm confusion, middleware ordering gap):**

```python
# Missing auth: admin endpoint without authentication check
@app.route("/admin/users", methods=["DELETE"])
def delete_user():
    user_id = request.args.get("id")
    db.execute("DELETE FROM users WHERE id = %s", (user_id,))
    return jsonify({"deleted": True})

# JWT algorithm confusion: accepting "none" algorithm
import jwt
def verify_token(token: str):
    # Attacker sets alg: "none" and removes signature
    payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256", "none"])
    return payload

# Middleware ordering: auth applied after route matching
app = Flask(__name__)
# Static files served before auth middleware runs
@app.route("/static/<path:filename>")
def serve_static(filename):
    return send_from_directory("static", filename)
# Auth middleware added later — static route bypasses it
```

**Correct (default-deny auth, strict JWT validation, auth-first middleware):**

```python
from functools import wraps

# Default-deny: decorator required on every route, public routes opt out
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        if not token:
            abort(401)
        try:
            request.user = verify_token(token)
        except jwt.InvalidTokenError:
            abort(401)
        return f(*args, **kwargs)
    return decorated

@app.route("/admin/users", methods=["DELETE"])
@require_auth
def delete_user():
    if request.user.get("role") != "admin":
        abort(403)  # Authorization check too
    user_id = request.args.get("id")
    db.execute("DELETE FROM users WHERE id = %s", (user_id,))
    return jsonify({"deleted": True})

# Strict JWT: explicit algorithm, validate expiration and issuer
def verify_token(token: str):
    return jwt.decode(
        token, SECRET_KEY,
        algorithms=["HS256"],  # Only accept expected algorithm
        options={"require": ["exp", "iss", "sub"]},
        issuer="myapp",
    )
```

Framework-specific: Django `@login_required` missing on views, Express.js middleware ordering, Spring `@PreAuthorize` on interfaces not enforced on implementations, Go middleware applied to router but not to handlers registered outside it. Always audit the route registration to confirm auth middleware covers all endpoints.
