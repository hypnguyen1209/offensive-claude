---
title: Prevent Path Traversal — Validate and Canonicalize All File Paths
impact: CRITICAL
impactDescription: Path traversal enables reading sensitive files like /etc/passwd, credentials, and source code
tags: path-traversal, directory-traversal, zip-slip, symlink, file-access
---

## Prevent Path Traversal — Validate and Canonicalize All File Paths

Path traversal occurs when user-controlled filenames or paths are used in file operations without proper validation. `../` sequences escape intended directories. Zip Slip attacks use archive entries with `../../` paths to write outside the extraction directory. Null byte injection in older runtimes truncates extensions (`file.txt%00.png`).

**Incorrect (user path concatenated without validation):**

```python
import os
import zipfile

# Direct path traversal: ../../../etc/passwd
@app.route("/files/<path:filename>")
def serve_file(filename):
    filepath = os.path.join(UPLOAD_DIR, filename)
    return send_file(filepath)  # filename = "../../etc/passwd"

# Zip Slip: archive entries with traversal paths
def extract_archive(zip_path: str, dest_dir: str):
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(dest_dir)  # Entry "../../etc/cron.d/backdoor" escapes
```

**Correct (canonicalize path and verify it stays within allowed directory):**

```python
from pathlib import Path
import zipfile

# Safe: resolve path and verify it's under the allowed directory
@app.route("/files/<path:filename>")
def serve_file(filename):
    base = Path(UPLOAD_DIR).resolve()
    filepath = (base / filename).resolve()
    if not filepath.is_relative_to(base):
        abort(403)  # Path traversal attempt
    if not filepath.is_file():
        abort(404)
    return send_file(filepath)

# Safe: validate each archive entry before extraction
def extract_archive(zip_path: str, dest_dir: str):
    dest = Path(dest_dir).resolve()
    with zipfile.ZipFile(zip_path) as zf:
        for entry in zf.namelist():
            target = (dest / entry).resolve()
            if not target.is_relative_to(dest):
                raise ValueError(f"Path traversal in archive: {entry}")
        zf.extractall(dest_dir)
```

In Go, `filepath.Join()` does NOT sanitize `..` — you must use `filepath.Clean()` then verify the result starts with the base directory. Path normalization mismatches between validator and filesystem (URL decoding, Unicode normalization, case folding) create bypass opportunities. On Windows, UNC paths (`\\attacker\share`) can trigger SSRF or credential theft.
