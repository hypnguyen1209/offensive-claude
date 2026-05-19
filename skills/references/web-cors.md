---
title: Configure CORS Correctly — Never Reflect Origin or Allow Null
impact: MEDIUM-HIGH
impactDescription: CORS misconfiguration enables cross-origin data theft from authenticated endpoints
tags: cors, cross-origin, origin-validation, access-control, browser-security
---

## Configure CORS Correctly — Never Reflect Origin or Allow Null

CORS misconfiguration occurs when the server reflects the request's Origin header as Access-Control-Allow-Origin without validation, effectively allowing any website to make authenticated cross-origin requests. Allowing `null` origin (triggered by sandboxed iframes) and regex matching with anchoring errors are common bypasses.

**Incorrect (origin reflection and weak regex validation):**

```python
# Reflects any origin: any website can read authenticated responses
@app.after_request
def add_cors(response):
    origin = request.headers.get("Origin")
    response.headers["Access-Control-Allow-Origin"] = origin  # Reflects ANY origin
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response

# Weak regex: evil-example.com matches the check
ALLOWED_PATTERN = re.compile(r"https://.*example\.com")  # Missing ^ anchor

@app.after_request
def add_cors(response):
    origin = request.headers.get("Origin", "")
    if ALLOWED_PATTERN.match(origin) or origin == "null":  # "null" is dangerous
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    return response
```

**Correct (strict allowlist with exact matching):**

```python
ALLOWED_ORIGINS = {
    "https://app.example.com",
    "https://admin.example.com",
}

@app.after_request
def add_cors(response):
    origin = request.headers.get("Origin", "")
    if origin in ALLOWED_ORIGINS:  # Exact match, no regex, no reflection
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Vary"] = "Origin"  # Critical for caching
    # If origin not allowed, no CORS headers = browser blocks the request
    return response

# For public APIs that don't need credentials
@app.after_request
def add_public_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    # Never combine * with Allow-Credentials: true
    return response
```

Always include `Vary: Origin` when the CORS response varies by origin — without it, CDNs and proxies may cache a response with one origin and serve it for another. Subdomain wildcards are dangerous if any subdomain allows user-controlled content (XSS on a subdomain = full CORS bypass).
