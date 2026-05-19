---
title: Verify Object Ownership on Every Access — Prevent IDOR and Privilege Escalation
impact: HIGH
impactDescription: IDOR is the most common API vulnerability — enables accessing any user's data by changing an ID
tags: idor, authorization, privilege-escalation, mass-assignment, access-control, bola
---

## Verify Object Ownership on Every Access — Prevent IDOR and Privilege Escalation

Insecure Direct Object Reference (IDOR) occurs when resource access uses user-supplied identifiers without verifying the requesting user owns or is authorized to access that resource. Horizontal escalation accesses other users' data; vertical escalation accesses admin functionality. Mass assignment allows users to set privileged fields by including unexpected parameters.

**Incorrect (ID-based access without ownership check, mass assignment):**

```python
# IDOR: any authenticated user can access any order by changing the ID
@app.route("/api/orders/<int:order_id>")
@require_auth
def get_order(order_id):
    order = db.execute("SELECT * FROM orders WHERE id = %s", (order_id,))
    return jsonify(order)  # No check that order belongs to request.user

# Mass assignment: saving entire request body allows privilege escalation
@app.route("/api/users/profile", methods=["PUT"])
@require_auth
def update_profile():
    data = request.get_json()
    # Attacker sends {"name": "hacker", "role": "admin", "is_verified": true}
    db.execute(
        "UPDATE users SET %s WHERE id = %%s" % ", ".join(f"{k} = %s" for k in data),
        (*data.values(), request.user["id"])
    )
```

**Correct (ownership verification and field-level allowlist):**

```python
# Safe: verify ownership before returning data
@app.route("/api/orders/<int:order_id>")
@require_auth
def get_order(order_id):
    order = db.execute(
        "SELECT * FROM orders WHERE id = %s AND user_id = %s",
        (order_id, request.user["id"])  # Ownership enforced in query
    )
    if not order:
        abort(404)  # Don't reveal whether order exists (use 404, not 403)
    return jsonify(order)

# Safe: explicit field allowlist prevents mass assignment
ALLOWED_PROFILE_FIELDS = {"name", "email", "bio"}

@app.route("/api/users/profile", methods=["PUT"])
@require_auth
def update_profile():
    data = request.get_json()
    safe_data = {k: v for k, v in data.items() if k in ALLOWED_PROFILE_FIELDS}
    if not safe_data:
        abort(400)
    db.execute(
        "UPDATE users SET %s WHERE id = %%s" % ", ".join(f"{k} = %s" for k in safe_data),
        (*safe_data.values(), request.user["id"])
    )
```

Check every endpoint that takes an ID parameter. Client-side authorization (hiding UI elements) is not security — server must enforce. GraphQL nested resolvers can bypass top-level authorization checks. Return 404 instead of 403 to avoid leaking resource existence.
