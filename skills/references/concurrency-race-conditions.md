---
title: Eliminate Race Conditions — Use Atomic Operations for Check-Then-Act Sequences
impact: HIGH
impactDescription: Race conditions enable double-spend, authentication bypass, and inventory oversell attacks
tags: race-condition, toctou, atomicity, double-spend, concurrent, locking
---

## Eliminate Race Conditions — Use Atomic Operations for Check-Then-Act Sequences

TOCTOU (Time-of-Check to Time-of-Use) vulnerabilities occur when a condition is checked and acted upon in separate non-atomic operations. Between the check and the use, a concurrent request can change the state, violating the assumption. Financial double-spend, coupon reuse, and authentication bypass are common exploitation targets.

**Incorrect (non-atomic check-then-act in balance deduction and coupon redemption):**

```python
# Double-spend: concurrent requests both pass the balance check
@app.route("/transfer", methods=["POST"])
def transfer():
    amount = int(request.form["amount"])
    # Thread 1: balance=100, amount=80 → check passes
    # Thread 2: balance=100, amount=80 → check passes (before T1 commits)
    user = db.execute("SELECT balance FROM accounts WHERE id = %s", (user_id,))
    if user.balance >= amount:  # CHECK
        # Both threads reach here with stale balance
        db.execute(
            "UPDATE accounts SET balance = balance - %s WHERE id = %s",
            (amount, user_id)  # USE: both deduct, balance goes to -60
        )
        return jsonify({"success": True})

# Coupon race: concurrent requests redeem same coupon multiple times
@app.route("/redeem", methods=["POST"])
def redeem_coupon():
    coupon = db.execute("SELECT * FROM coupons WHERE code = %s", (code,))
    if not coupon.used:  # CHECK: both threads see used=False
        apply_discount(coupon)
        db.execute("UPDATE coupons SET used = TRUE WHERE code = %s", (code,))
        # USE: discount applied twice
```

**Correct (atomic operations with database-level locking):**

```python
# Safe: atomic conditional update — check and act in single statement
@app.route("/transfer", methods=["POST"])
def transfer():
    amount = int(request.form["amount"])
    # Single atomic statement: deducts only if balance sufficient
    result = db.execute(
        "UPDATE accounts SET balance = balance - %s "
        "WHERE id = %s AND balance >= %s "
        "RETURNING balance",
        (amount, user_id, amount)
    )
    if result.rowcount == 0:
        return jsonify({"error": "Insufficient balance"}), 400
    return jsonify({"success": True, "new_balance": result.fetchone().balance})

# Safe: atomic coupon redemption with row-level lock
@app.route("/redeem", methods=["POST"])
def redeem_coupon():
    # SELECT FOR UPDATE + conditional update in single transaction
    result = db.execute(
        "UPDATE coupons SET used = TRUE "
        "WHERE code = %s AND used = FALSE "
        "RETURNING id",
        (code,)
    )
    if result.rowcount == 0:
        return jsonify({"error": "Coupon already used"}), 400
    apply_discount(code)
    return jsonify({"success": True})
```

Web-specific race targets: two-factor authentication lockout bypass (concurrent OTP submissions), file upload processing before virus scan completes, and inventory reservation during checkout. Use database constraints, `SELECT FOR UPDATE`, or application-level distributed locks.
