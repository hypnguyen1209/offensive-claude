---
title: Protect State-Changing Operations From CSRF With Tokens and SameSite Cookies
impact: MEDIUM-HIGH
impactDescription: CSRF enables attackers to perform actions as authenticated users without their knowledge
tags: csrf, cross-site-request-forgery, samesite, token, state-change
---

## Protect State-Changing Operations From CSRF With Tokens and SameSite Cookies

CSRF exploits the browser's automatic cookie inclusion on cross-origin requests to perform unauthorized state-changing operations. APIs relying solely on cookies for authentication are vulnerable. SameSite cookie attributes provide baseline protection, but explicit CSRF tokens remain necessary for full coverage.

**Incorrect (state changes via GET, no CSRF protection on forms):**

```python
# State change via GET: trivially exploitable with <img> tag
@app.route("/delete-account")
@require_auth
def delete_account():
    db.execute("DELETE FROM users WHERE id = %s", (request.user["id"],))
    return redirect("/")
    # Attack: <img src="https://target.com/delete-account"> on any page

# POST without CSRF token: exploitable with hidden form auto-submit
@app.route("/transfer", methods=["POST"])
@require_auth
def transfer():
    to_account = request.form["to"]
    amount = request.form["amount"]
    execute_transfer(request.user["id"], to_account, amount)
    # Attack: hidden form on attacker's page auto-submits via JavaScript
```

**Correct (CSRF tokens, SameSite cookies, custom header verification):**

```python
import secrets

# Generate CSRF token tied to session
def get_csrf_token(session_id: str) -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]

# Verify CSRF token on all state-changing requests
def verify_csrf(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        if not token or not hmac.compare_digest(token, session.get("csrf_token", "")):
            abort(403, "CSRF token invalid")
        return f(*args, **kwargs)
    return decorated

@app.route("/transfer", methods=["POST"])
@require_auth
@verify_csrf
def transfer():
    to_account = request.form["to"]
    amount = request.form["amount"]
    execute_transfer(request.user["id"], to_account, amount)

# Set SameSite on session cookies as defense-in-depth
resp.set_cookie("session", token, samesite="Lax", secure=True, httponly=True)

# For SPAs: require custom header (browsers don't send custom headers cross-origin)
# X-Requested-With: XMLHttpRequest as CSRF defense
```

SameSite=Lax allows GET requests from cross-origin navigations — never perform state changes on GET. For APIs consumed by SPAs, requiring a custom header (e.g., `X-CSRF-Token`) is effective since browsers don't allow cross-origin custom headers without CORS preflight approval. Subdomain takeover can set cookies for the parent domain, undermining double-submit cookie patterns.
