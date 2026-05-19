---
title: Eliminate Default Credentials — Require Credential Setup on First Use
impact: CRITICAL
impactDescription: Default credentials are trivially exploitable and frequently targeted by automated botnets and mass scanners
tags: default-credentials, default-password, first-run-setup, credential-rotation, cwe-1392
---

## Eliminate Default Credentials — Require Credential Setup on First Use

Default credentials (CWE-1392) ship products with well-known usernames and passwords (admin/admin, root/root, or documented default keys). Attackers harvest these from manuals, firmware analysis, and public credential lists. 10 high-severity CVEs in the last 6 months (avg CVSS 9.0). Automated scanners like Mirai and its variants continuously probe for default credentials on exposed services.

**Incorrect (shipping with default credentials and optional change):**

```python
# Default admin account created on install
DEFAULT_ADMIN = {"username": "admin", "password": "admin123"}

def initialize_database():
    if not User.query.filter_by(username="admin").first():
        User.create(**DEFAULT_ADMIN, role="superadmin")
        # "Users should change the default password" — they won't

# Default API key in config file
config = {
    "api_key": "changeme-default-key-12345",  # Documented in README
    "admin_token": "default-admin-token",
}
```

**Correct (force unique credential creation, no defaults):**

```python
import secrets
import sys

def initialize_database():
    if not User.query.filter_by(role="superadmin").first():
        # Generate random initial password, display once
        initial_password = secrets.token_urlsafe(24)
        User.create(
            username="admin",
            password=hash_password(initial_password),
            role="superadmin",
            must_change_password=True,  # Force change on first login
        )
        print(f"Initial admin password: {initial_password}", file=sys.stderr)
        print("This password will not be shown again.", file=sys.stderr)

def get_api_key():
    key = os.environ.get("API_KEY")
    if not key:
        raise RuntimeError(
            "API_KEY environment variable is required. "
            "Generate one with: python -c 'import secrets; print(secrets.token_urlsafe(32))'"
        )
    return key
```

Never ship software with functional default credentials. Require setup wizards that force credential creation on first use. If initial credentials are necessary, generate them randomly per-installation and display them exactly once. Flag `must_change_password` to enforce rotation. Audit all configuration files, Docker images, and infrastructure-as-code for checked-in defaults.
