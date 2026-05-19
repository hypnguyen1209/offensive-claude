---
title: Enforce Brute Force Protection — Rate Limit and Lock Authentication Endpoints
impact: HIGH
impactDescription: Missing brute force protection allows credential stuffing and password spraying to compromise accounts at scale
tags: brute-force, rate-limiting, account-lockout, credential-stuffing, cwe-307
---

## Enforce Brute Force Protection — Rate Limit and Lock Authentication Endpoints

Missing brute force protection (CWE-307) allows attackers unlimited authentication attempts, enabling credential stuffing (testing leaked password lists), password spraying (common passwords across many accounts), and OTP brute forcing. 17 high-severity CVEs in the last 6 months (avg CVSS 8.2), including CVE-2025-64102 (Zitadel OTP brute force, CVSS 9.8) and CVE-2025-8679 (ExtremeGuest captive portal bypass).

**Incorrect (no rate limiting or lockout on login attempts):**

```python
@app.route('/api/login', methods=['POST'])
def login():
    username = request.json['username']
    password = request.json['password']
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        return jsonify({"token": create_token(user)})
    return jsonify({"error": "Invalid credentials"}), 401  # Unlimited attempts

@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    code = request.json['code']
    if code == session.get('otp_code'):  # 4-digit OTP = 10000 attempts to crack
        return jsonify({"verified": True})
    return jsonify({"error": "Invalid code"}), 401  # No attempt tracking
```

**Correct (progressive delays, account lockout, and rate limiting):**

```python
from datetime import datetime, timedelta
from flask_limiter import Limiter

limiter = Limiter(app, default_limits=["100/hour"])
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15)
OTP_MAX_ATTEMPTS = 3

@app.route('/api/login', methods=['POST'])
@limiter.limit("10/minute", key_func=lambda: request.json.get('username', ''))
def login():
    username = request.json['username']
    user = User.query.filter_by(username=username).first()

    if user and user.locked_until and user.locked_until > datetime.utcnow():
        return jsonify({"error": "Account locked, try again later"}), 429

    if user and user.check_password(request.json['password']):
        user.failed_attempts = 0
        db.session.commit()
        return jsonify({"token": create_token(user)})

    # Track failures per account
    if user:
        user.failed_attempts = (user.failed_attempts or 0) + 1
        if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
            user.locked_until = datetime.utcnow() + LOCKOUT_DURATION
        db.session.commit()

    return jsonify({"error": "Invalid credentials"}), 401

@app.route('/api/verify-otp', methods=['POST'])
@limiter.limit("3/minute")
def verify_otp():
    otp_state = session.get('otp_state', {})
    if otp_state.get('attempts', 0) >= OTP_MAX_ATTEMPTS:
        session.pop('otp_code', None)  # Invalidate OTP after max attempts
        return jsonify({"error": "Too many attempts, request new code"}), 429

    otp_state['attempts'] = otp_state.get('attempts', 0) + 1
    session['otp_state'] = otp_state

    if request.json['code'] == session.get('otp_code'):
        return jsonify({"verified": True})
    return jsonify({"error": "Invalid code"}), 401
```

Rate limit by both IP and account identifier. Use progressive delays (exponential backoff) rather than immediate hard lockouts to avoid denial-of-service against legitimate users. For OTPs, limit to 3-5 attempts then require a new code. Use CAPTCHA after 3 failed attempts. Log all failed authentication attempts for security monitoring.
