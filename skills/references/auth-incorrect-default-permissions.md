---
title: Set Restrictive Default Permissions — Never Deploy Resources World-Readable or World-Writable
impact: HIGH
impactDescription: Overly permissive defaults allow local attackers to escalate privileges by modifying executables, configs, or sensitive data
tags: file-permissions, default-permissions, privilege-escalation, least-privilege, cwe-276
---

## Set Restrictive Default Permissions — Never Deploy Resources World-Readable or World-Writable

Incorrect default permissions (CWE-276) occur when files, directories, services, or IPC endpoints are created with overly permissive access controls. Local attackers can read sensitive configuration (database credentials, API keys), replace service executables with malicious binaries, or modify config files to achieve privilege escalation. 14 high-severity CVEs in the last 6 months (avg CVSS 8.0). Common vectors: service installers that set world-writable program directories, log files containing secrets with 0666 permissions, and Docker volumes mounted with no access restrictions.

**Incorrect (overly permissive file and directory creation):**

```python
import os
import stat

# Creating config file with world-readable permissions
def write_config(path, db_password):
    with open(path, 'w') as f:
        f.write(f"DB_PASSWORD={db_password}\n")
    os.chmod(path, 0o644)  # World-readable — any local user can read secrets

# Creating directory with world-writable permissions
os.makedirs("/opt/myapp/plugins", mode=0o777)  # Anyone can plant malicious plugins

# Writing log file with default umask (often 0022 → 0644)
with open("/var/log/myapp/audit.log", "a") as f:
    f.write(f"Auth token: {token}\n")  # Secrets in world-readable logs
```

```bash
# Service installer with writable program directory
install -d -m 0777 /opt/myservice
install -m 0755 myservice /opt/myservice/  # Binary in world-writable dir — replaceable

# Docker volume with no restrictions
docker run -v /opt/data:/data myapp  # Container files inherit host permissions
```

**Correct (restrictive defaults, explicit minimal permissions):**

```python
import os
import stat

def write_config(path, db_password):
    # Set restrictive umask before creating sensitive files
    old_umask = os.umask(0o077)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(f"DB_PASSWORD={db_password}\n")
    finally:
        os.umask(old_umask)

# Create directories with restricted access
os.makedirs("/opt/myapp/plugins", mode=0o750, exist_ok=True)
# Ensure ownership is correct
import shutil
shutil.chown("/opt/myapp/plugins", user="myapp", group="myapp")

# Logs should never contain secrets, and should be group-readable at most
def setup_logging(log_path):
    fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
    return os.fdopen(fd, 'a')
```

```bash
# Service installer with proper permissions
install -d -m 0755 -o root -g root /opt/myservice
install -m 0755 -o root -g root myservice /opt/myservice/  # Only root can modify

# Docker with explicit user and read-only mount
docker run --user 1000:1000 -v /opt/data:/data:ro myapp
```

Apply the principle of least privilege: files should be owned by the service account and readable only by that account (0600 for secrets, 0640 for logs, 0750 for directories). Set umask to 0077 in service startup scripts. Audit installed file permissions with `find / -perm -002 -type f` (world-writable). For Windows services, ensure program directories are not writable by non-admin users — this is the most common vector for unquoted service path exploits (CWE-428).
