---
title: Verify Code Integrity Before Execution — Sign and Hash All Downloaded Code
impact: HIGH
impactDescription: Executing code without integrity verification enables supply chain attacks through compromised downloads
tags: code-integrity, signature-verification, checksum, supply-chain, cwe-494
---

## Verify Code Integrity Before Execution — Sign and Hash All Downloaded Code

Download of code without integrity check (CWE-494) occurs when applications fetch and execute remote code (updates, plugins, scripts) without verifying cryptographic signatures or checksums. MitM attackers or compromised mirrors can substitute malicious payloads. 12 high-severity CVEs in the last 6 months (avg CVSS 8.7). Common vectors: auto-update mechanisms fetching over HTTP, install scripts piped to shell without verification, and plugin systems loading unsigned code.

**Incorrect (executing downloaded code without verification):**

```bash
# Classic anti-pattern: pipe remote script to shell
curl -fsSL https://install.example.com/setup.sh | bash

# Downloading binary without checksum verification
wget https://releases.example.com/tool-v2.0.tar.gz
tar xzf tool-v2.0.tar.gz && ./tool/install.sh
```

```python
# Auto-updater that trusts the download
def update_application():
    response = requests.get("https://updates.example.com/latest.zip")
    with open("/tmp/update.zip", "wb") as f:
        f.write(response.content)
    subprocess.run(["unzip", "-o", "/tmp/update.zip", "-d", "/opt/app/"])  # No verification
```

**Correct (verify signatures and checksums before execution):**

```bash
# Download, verify checksum, then execute
curl -fsSL -o setup.sh https://install.example.com/setup.sh
curl -fsSL -o setup.sh.sha256 https://install.example.com/setup.sh.sha256
echo "$(cat setup.sh.sha256)  setup.sh" | sha256sum --check --strict || exit 1
bash setup.sh

# Better: verify GPG signature
curl -fsSL -o tool.tar.gz https://releases.example.com/tool-v2.0.tar.gz
curl -fsSL -o tool.tar.gz.sig https://releases.example.com/tool-v2.0.tar.gz.sig
gpg --verify tool.tar.gz.sig tool.tar.gz || exit 1
```

```python
import hashlib
import subprocess

EXPECTED_HASH = "a1b2c3d4..."  # Pinned in source or fetched from separate trusted channel

def update_application():
    response = requests.get("https://updates.example.com/latest.zip")
    actual_hash = hashlib.sha256(response.content).hexdigest()

    if actual_hash != EXPECTED_HASH:
        raise SecurityError(f"Update hash mismatch: expected {EXPECTED_HASH}, got {actual_hash}")

    # Verify GPG signature for stronger guarantee
    with open("/tmp/update.zip", "wb") as f:
        f.write(response.content)
    result = subprocess.run(
        ["gpg", "--verify", "/tmp/update.zip.sig", "/tmp/update.zip"],
        capture_output=True
    )
    if result.returncode != 0:
        raise SecurityError("Update signature verification failed")
```

Use HTTPS for all downloads (necessary but not sufficient — compromised servers still serve malicious files over HTTPS). Pin expected checksums in a separate channel from the download. Prefer cryptographic signatures (GPG, Sigstore) over checksums alone. For container images, use digest pinning (`image@sha256:...`) instead of mutable tags.
