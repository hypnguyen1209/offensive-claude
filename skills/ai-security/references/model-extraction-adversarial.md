# Model Extraction, Membership Inference & Adversarial ML

OWASP LLM02:2025 (Sensitive Information Disclosure) + LLM10:2025 (Unbounded Consumption,
which covers model theft via querying). MITRE ATLAS `AML.T0024` (Exfiltration via ML
Inference API), `AML.T0048` (Extract ML Model), `AML.T0043` (Craft Adversarial Data).
CWE-200 (Information Exposure), CWE-1039 (Inadequate ML robustness).

## 1. Black-box model extraction / distillation

Goal: clone a proprietary model's *behavior* from API access only. Query with diverse
inputs, collect outputs, train a surrogate. A 2024 study extracted a fine-tuned clinical
LLM to **94%** of original task performance for **<$1,000** in queries — no defense fully
prevents this when the API answers at all.

- **LoRD** (Locality Reinforced Distillation, arXiv:2409.02718, 2024) — LLM-specific:
  treats extraction as an RL-style alignment procedure rather than naive DNN distillation,
  cutting query budget and mitigating watermark protection via exploration-based stealing.
- **MiniLLM** (Gu et al., 2024) — reverse-KL sequence-level distillation when only text
  (no logits) is available.
- **Logit access** dramatically lowers cost — if the API returns `logprobs`/`top_logprobs`,
  the surrogate learns from soft targets, not just argmax text.

`scripts/model_extractor.py extract` runs the loop: sample a prompt distribution, query the
target (capturing logprobs if exposed), and write the (prompt, response, logprobs) dataset
ready for surrogate fine-tuning, with a query-budget cap.

## 2. Stealing *part* of a production model (Carlini et al., arXiv:2403.06634, 2024)

Even closed APIs leak architecture: by querying with carefully chosen inputs and solving a
linear system over the returned logit *vectors*, the **final embedding-projection layer**
(hidden dimension, and the layer's weights up to symmetry) can be recovered for as little as
a few dollars per model. Pushed providers to clip/round logits and cap `top_logprobs`.
`model_extractor.py probe-dim` implements the hidden-dimension recovery: gather logit
vectors for many prompts, build the matrix, and report its numerical rank ≈ hidden size.

## 3. Membership inference (MIA) — training-data exposure

Does data point X appear in the training set? Privacy violation; precursor to data
extraction. Core signal: members get *lower loss / higher confidence* (memorization).

```text
# Metric-based (loss/perplexity threshold) — what model_extractor.py membership uses:
score(X) = -avg_token_logprob(model, X)          # lower perplexity => more likely member
member if score(X) < tau   (tau calibrated on known-out reference text)
# Reference/LiRA-style: compare to a reference model's loss to cut false positives.
```

Caveats from 2024-2025 research (cite honestly in findings):
- Duan et al., "Do Membership Inference Attacks Work on LLMs?" (arXiv:2402.07841) — for
  large pretraining corpora, naive MIA often barely beats chance.
- Das, Zhang, Tramèr (2025) — "blind baselines" (exploiting temporal/distribution shift)
  can beat reported MIAs; validate against a proper blind baseline before claiming success.
- Stronger signals: internal-state probing (Lumia, arXiv:2411.19876) and low-confidence /
  "hard token" exploitation (2025) where white/grey-box access exists.

So: MIA is reliable for **fine-tuned / small / overfit** models and memorized records;
treat headline ASR on frontier pretrained models skeptically.

## 4. Model inversion

Reconstruct a representative input for a target class/identity from gradients or repeated
queries. High impact on models over private data (faces, medical). White-box version
(`model_extractor.py inversion`, PyTorch) optimizes a random input to maximize the target
class logit with a realism regularizer:

```python
import torch, torch.nn.functional as F
def model_inversion(model, target_class, shape, lr=0.05, steps=1500):
    x = torch.randn(1, *shape, requires_grad=True)
    opt = torch.optim.Adam([x], lr=lr)
    for _ in range(steps):
        opt.zero_grad()
        loss = -F.log_softmax(model(x), 1)[0, target_class] + 1e-2 * x.norm()
        loss.backward(); opt.step(); x.data.clamp_(0, 1)
    return x.detach()      # e.g. average face of the target identity
```

## 5. Adversarial suffixes — GCG (white-box)

Greedy Coordinate Gradient (Zou et al., 2023): optimize a suffix that forces an affirmative
target prefix ("Sure, here is..."). Per step: compute the gradient of target-token loss
w.r.t. the one-hot of each suffix position, take top-k candidate token swaps per position,
batch-evaluate, keep the best.

```python
# GCG core step (white-box, HF causal LM) — full loop in scripts/model_extractor.py gcg
def gcg_step(model, tok, ids, adv_slice, target_ids, topk=256, batch=512):
    import torch
    emb = model.get_input_embeddings().weight                    # (V, d)
    onehot = torch.zeros(ids[adv_slice].numel(), emb.size(0), device=model.device)
    onehot.scatter_(1, ids[adv_slice].unsqueeze(1), 1.0).requires_grad_()
    x = (onehot @ emb).unsqueeze(0)                              # differentiable embeds
    full = torch.cat([model.get_input_embeddings()(ids[:adv_slice.start]).unsqueeze(0),
                      x,
                      model.get_input_embeddings()(ids[adv_slice.stop:]).unsqueeze(0)], 1)
    logits = model(inputs_embeds=full).logits
    loss = torch.nn.functional.cross_entropy(
        logits[0, -target_ids.numel()-1:-1], target_ids)
    loss.backward()
    cand = (-onehot.grad).topk(topk, dim=1).indices              # best swaps per position
    # ... sample `batch` single-token swaps from cand, re-score, keep min-loss candidate
    return cand
```

2024-2025 variants: **AmpleGCG** & **Universal Jailbreak Suffixes** (better cross-model
transfer), **Joint-GCG** (adapts the attack to RAG), ensemble methods. Transfer suffixes
are high-perplexity → detectable.

## Detection

- **Extraction/MIA**: per-key/IP query-rate + anomaly limits; cluster near-duplicate or
  systematically-varied prompts (extraction sweeps look nothing like human use);
  **clip/round/disable logprobs** and cap `top_logprobs` (kills Carlini-class + soft-label
  distillation); **output watermarking** so a stolen surrogate is provable; per-account
  budget caps (LLM10 unbounded consumption).
- **Adversarial suffix**: input **perplexity filter** (garbled suffix spikes PPL);
  paraphrase / re-tokenize defense before inference.

Sigma (API gateway):

```yaml
title: Model Extraction / Membership-Inference Query Pattern
logsource: { product: llm_gateway }
detection:
  high_volume:
    api_key|exists: true
    request_count_5m|gte: 800
  logprob_harvest:
    params.logprobs|exists: true
    params.top_logprobs|gte: 5
  near_dup:                              # enrichment: % of near-duplicate prompts per key
    prompt_dup_ratio_15m|gte: 0.6
  condition: high_volume and (logprob_harvest or near_dup)
level: medium
```

IOCs: sustained high-QPS from one key/IP; requests demanding logprobs/top_logprobs;
templated prompt sweeps; many queries that differ only by a trailing garbled suffix.

## OPSEC

- Extraction is *loud by volume* — distribute across keys/IPs/time, mix in human-like
  traffic, and stay under per-account budget alerts. logprob endpoints get disabled when
  abuse is detected; grab soft labels early.
- White-box GCG / inversion need local weights (open model or a stolen surrogate) — run
  offline; do not hammer the production API computing gradients.
- Report honestly: distinguish *functional* clone vs *architectural* extraction, and
  validate MIA against a blind baseline before claiming training-data membership.
- Cleanup: rotate/abandon test keys; do not retain extracted PII beyond the ROE evidence
  requirement; document lawful basis for any reconstructed personal data.

## References

- Carlini et al., "Stealing Part of a Production Language Model," arXiv:2403.06634 (2024).
- "Yes, My LoRD: Guiding LM Extraction with Locality Reinforced Distillation," arXiv:2409.02718.
- "A Survey on Model Extraction Attacks and Defenses for LLMs," arXiv:2506.22521 / KDD 2025.
- Duan et al., "Do Membership Inference Attacks Work on LLMs?" arXiv:2402.07841; Das/Zhang/Tramèr, "Blind Baselines Beat MIAs," 2025.
- Zou et al., "Universal and Transferable Adversarial Attacks (GCG)," 2023; AmpleGCG (Liao & Sun, 2024); Joint-GCG (2025); "Resurgence of GCG," arXiv:2509.00391.
- OWASP LLM02/LLM10:2025; MITRE ATLAS AML.T0024/AML.T0048/AML.T0043.
