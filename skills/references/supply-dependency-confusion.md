---
title: Defend Against Supply Chain Attacks — Pin Dependencies, Verify Integrity, Audit Packages
impact: MEDIUM
impactDescription: Supply chain compromise can backdoor entire applications through a single malicious dependency
tags: supply-chain, dependency-confusion, typosquatting, npm-audit, lock-file, cve
---

## Defend Against Supply Chain Attacks — Pin Dependencies, Verify Integrity, Audit Packages

Supply chain attacks exploit trust in third-party code: dependency confusion claims private package names on public registries, typosquatting registers near-misspellings of popular packages, and AI-generated code references hallucinated package names that attackers register ("slopsquatting"). Post-install scripts in npm/pip can execute arbitrary code during `install`.

**Incorrect (unpinned deps, no lock file verification, unaudited packages):**

```json
{
  "dependencies": {
    "express": "^4.18.0",
    "lodash": "*",
    "internal-auth-lib": "latest"
  }
}
```

```python
# requirements.txt — no version pins, no hashes
requests
flask
pyyaml
internal-utils
```

```python
# Loading a model from untrusted source without verification
from transformers import AutoModel
model = AutoModel.from_pretrained(
    "random-user/suspicious-model",
    trust_remote_code=True  # Downloads and executes arbitrary Python
)
```

**Correct (pinned versions, lock files, hash verification, auditing):**

```json
{
  "dependencies": {
    "express": "4.18.2",
    "lodash": "4.17.21"
  },
  "overrides": {},
  "scripts": {
    "preinstall": "npx npm-audit-resolver",
    "postinstall": ""
  }
}
```

```python
# requirements.txt — pinned with hashes for integrity verification
requests==2.31.0 \
    --hash=sha256:942c5a758f98d790eaed1a29cb6eefc7f0edf3fcb0fce8aea3fbd5951d bdf0 \
    --hash=sha256:58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e01 3003
flask==3.0.0 \
    --hash=sha256:21128f47e4e3b9d597a3e8521a329bf56909b690fcc3fa3e477725aa81 af000
```

```python
# Safe model loading: use SafeTensors, disable remote code
from safetensors.torch import load_file
from transformers import AutoModel

# SafeTensors: contains only tensor data, cannot execute code
weights = load_file("model.safetensors")

# If using from_pretrained, never trust remote code
model = AutoModel.from_pretrained(
    "verified-org/audited-model",
    trust_remote_code=False  # Default — never set to True for untrusted models
)
```

Commit lock files (package-lock.json, Pipfile.lock, Cargo.lock) and verify them in CI. Run `npm audit`, `pip-audit`, `cargo-audit`, or `govulncheck` regularly. For private packages, use scoped registries or namespace reservation on public registries to prevent confusion attacks.
