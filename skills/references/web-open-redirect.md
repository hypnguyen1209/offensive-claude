---
title: Prevent Open Redirects — Validate Redirect Targets Against an Allowlist
impact: HIGH
impactDescription: Open redirects enable phishing attacks that abuse legitimate domain trust and can leak OAuth tokens via redirect_uri
tags: open-redirect, url-validation, phishing, oauth-redirect, cwe-601
---

## Prevent Open Redirects — Validate Redirect Targets Against an Allowlist

Open redirect (CWE-601) occurs when an application accepts a user-controlled URL parameter and redirects to it without validation. Attackers craft links that appear to originate from a trusted domain but redirect victims to phishing sites. OAuth flows are especially dangerous — a redirect_uri open redirect leaks authorization codes to attacker-controlled servers. 9 high-severity CVEs in the last 6 months (avg CVSS 8.2), including CVE-2026-0573 (GitHub Enterprise token leak via open redirect).

**Incorrect (redirect to user-supplied URL without validation):**

```python
@app.route('/login')
def login():
    next_url = request.args.get('next', '/')
    # Attacker: /login?next=https://evil.com/phishing
    if authenticate(request):
        return redirect(next_url)  # Redirects to attacker's site

# URL "validation" that can be bypassed
def is_safe_redirect(url):
    return url.startswith('/')  # Bypassed with //evil.com (protocol-relative)
                                 # or /\evil.com or /%2F%2Fevil.com
```

**Correct (allowlist-based validation with strict URL parsing):**

```python
from urllib.parse import urlparse

ALLOWED_HOSTS = {'app.example.com', 'www.example.com'}

def safe_redirect_url(url, default='/'):
    """Validate redirect URL is relative or points to an allowed host."""
    if not url:
        return default

    parsed = urlparse(url)

    # Reject any URL with a scheme or netloc (absolute URLs)
    # Also catches //evil.com (scheme-relative), javascript:, data:
    if parsed.scheme or parsed.netloc:
        if parsed.netloc not in ALLOWED_HOSTS:
            return default
        if parsed.scheme not in ('http', 'https'):
            return default

    # Reject path-based bypasses
    if url.startswith('//') or url.startswith('/\\'):
        return default

    return url

@app.route('/login')
def login():
    next_url = safe_redirect_url(request.args.get('next'))
    if authenticate(request):
        return redirect(next_url)
```

For OAuth `redirect_uri`, use exact string matching against pre-registered URIs — never pattern matching or subdomain matching. Strip query parameters from comparison to prevent parameter injection. Log blocked redirect attempts for abuse detection.
