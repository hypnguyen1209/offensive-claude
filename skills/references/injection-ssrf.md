---
title: Block Server-Side Request Forgery — Validate URLs Against Internal Network Access
impact: CRITICAL
impactDescription: SSRF enables access to cloud metadata, internal services, and credential theft
tags: ssrf, url-validation, dns-rebinding, metadata, internal-network
---

## Block Server-Side Request Forgery — Validate URLs Against Internal Network Access

SSRF occurs when an application makes HTTP requests to user-controlled URLs, allowing attackers to reach internal services, cloud metadata endpoints (169.254.169.254), and localhost services. URL validation is frequently bypassed through DNS rebinding, redirect chains, alternative IP representations, and URL parser inconsistencies.

**Incorrect (user URL fetched without validation or with bypassable checks):**

```python
import requests

# Direct SSRF: fetches any URL including internal services
@app.route("/preview")
def preview_url():
    url = request.args.get("url")
    response = requests.get(url)  # url = "http://169.254.169.254/latest/meta-data/"
    return response.text

# Bypassable validation: only checks string prefix
def fetch_safe(url: str):
    if url.startswith("http://localhost") or url.startswith("http://127."):
        raise ValueError("Internal URL blocked")
    # Bypasses: http://0x7f000001, http://[::1], http://2130706433
    # DNS rebinding: attacker domain resolves to 127.0.0.1
    # Redirect: allowed host 302 redirects to internal host
    return requests.get(url).text
```

**Correct (resolve DNS before request, validate IP against allowlist):**

```python
import ipaddress
import socket
import requests
from urllib.parse import urlparse

BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
]

def is_internal_ip(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str)
    return any(ip in network for network in BLOCKED_NETWORKS)

def fetch_safe(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP(S) allowed")

    # Resolve DNS BEFORE making request to prevent DNS rebinding
    hostname = parsed.hostname
    ip = socket.getaddrinfo(hostname, parsed.port or 443)[0][4][0]
    if is_internal_ip(ip):
        raise ValueError("Internal IP blocked")

    # Disable redirects to prevent redirect-based bypass
    response = requests.get(url, allow_redirects=False, timeout=5)
    if response.is_redirect:
        raise ValueError("Redirects not allowed")
    return response.text
```

PDF generators, image processors, webhook implementations, and GraphQL federation endpoints are common SSRF vectors. Always resolve DNS before connecting and block all RFC 1918/link-local addresses.
