---
title: Prevent TOCTOU in File Operations — Use File Descriptors Instead of Paths
impact: HIGH
impactDescription: File system TOCTOU enables symlink attacks for privilege escalation and arbitrary file access
tags: toctou, file-system, symlink, race-condition, privilege-escalation, fd
---

## Prevent TOCTOU in File Operations — Use File Descriptors Instead of Paths

File system TOCTOU occurs when a program checks a file's properties (permissions, existence, type) and then operates on it by path — between the check and the operation, an attacker replaces the file with a symlink to a sensitive target. This is especially dangerous in setuid programs and services running as root.

**Incorrect (path-based check followed by path-based operation):**

```python
import os

# TOCTOU: attacker replaces file with symlink between check and open
def safe_write(filepath: str, data: str):
    # CHECK: verify file is not a symlink
    if os.path.islink(filepath):
        raise ValueError("Symlinks not allowed")
    # RACE WINDOW: attacker does: rm filepath && ln -s /etc/passwd filepath
    # USE: writes to /etc/passwd instead
    with open(filepath, "w") as f:
        f.write(data)

# TOCTOU in temp file creation
def process_upload(upload_path: str):
    temp_path = f"/tmp/upload_{os.getpid()}"
    if not os.path.exists(temp_path):  # CHECK
        # RACE: attacker creates symlink at temp_path
        with open(temp_path, "w") as f:  # USE: writes through symlink
            f.write(read_upload(upload_path))
```

**Correct (file descriptor-based operations and atomic creation):**

```python
import os
import tempfile

# Safe: open with O_NOFOLLOW rejects symlinks atomically
def safe_write(filepath: str, data: str):
    # O_NOFOLLOW: fails if path is a symlink (atomic check-and-open)
    # O_CREAT | O_EXCL: fails if file already exists (atomic create)
    fd = os.open(filepath, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o644)
    try:
        os.write(fd, data.encode())
    finally:
        os.close(fd)

# Safe: tempfile creates with unique name atomically
def process_upload(upload_path: str):
    # mkstemp atomically creates a unique file — no race window
    fd, temp_path = tempfile.mkstemp(prefix="upload_", dir="/tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(read_upload(upload_path))
        process_file(temp_path)
    finally:
        os.unlink(temp_path)
```

In C, use `fstat()` on the file descriptor instead of `stat()` on the path to verify file properties after opening. Use `openat()` with `O_NOFOLLOW` for directory-relative operations. Signal handlers calling non-reentrant functions (malloc, printf, lock acquisition) are a related TOCTOU class — the signal can arrive between any two instructions.
