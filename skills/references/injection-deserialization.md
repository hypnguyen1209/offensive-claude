---
title: Never Deserialize Untrusted Data — Use Safe Formats and Strict Type Validation
impact: CRITICAL
impactDescription: Insecure deserialization enables arbitrary code execution through gadget chains
tags: deserialization, pickle, yaml, java-serialization, rce, model-loading
---

## Never Deserialize Untrusted Data — Use Safe Formats and Strict Type Validation

Deserialization of untrusted data frequently enables arbitrary code execution through "gadget chains" — sequences of existing class methods triggered during object reconstruction. This affects Python pickle, Java ObjectInputStream, PHP unserialize, Ruby Marshal, .NET BinaryFormatter, and ML model files that use these formats internally.

**Incorrect (deserializing untrusted data with unsafe loaders):**

```python
import pickle
import yaml

# Pickle RCE: loading untrusted pickle executes arbitrary code
def load_session(session_data: bytes):
    return pickle.loads(session_data)  # Attacker crafts pickle with os.system()

# YAML RCE: yaml.load without SafeLoader executes Python objects
def load_config(config_str: str):
    return yaml.load(config_str)  # !!python/object/apply:os.system ["rm -rf /"]

# ML model loading: PyTorch .pt files use pickle internally
import torch
def load_model(model_path: str):
    return torch.load(model_path)  # Arbitrary code execution via pickle
```

**Correct (safe loaders, safe formats, and type validation):**

```python
import json
import yaml
from safetensors.torch import load_file

# Safe: JSON cannot execute code during parsing
def load_session(session_data: str):
    data = json.loads(session_data)
    return Session(**data)  # Explicit construction from validated fields

# Safe: yaml.safe_load only allows basic types
def load_config(config_str: str):
    return yaml.safe_load(config_str)  # Rejects Python object tags

# Safe: SafeTensors format contains only tensor data, no code
def load_model(model_path: str):
    return load_file(model_path)  # Cannot execute arbitrary code

# If pickle is unavoidable, use weights_only=True (PyTorch 2.6+)
import torch
def load_model_legacy(model_path: str):
    return torch.load(model_path, weights_only=True)
```

Hugging Face `from_pretrained()` with `trust_remote_code=True` is an explicit RCE vector — it downloads and executes arbitrary Python. Java applications should avoid `ObjectInputStream` on untrusted data entirely; use JSON/protobuf instead. Node.js libraries like `node-serialize` that reconstruct functions from serialized data are inherently unsafe.
