# Automated & Multi-Turn Jailbreaks

## Theory / Mechanism

A *jailbreak* makes an aligned model produce content/actions its safety policy forbids. For an
**agent** this is not just "say bad words" — it is unlocking a tool call, a memory write, or an
exfil action. Manual one-shot jailbreaks are brittle; modern red teaming uses **automated,
adaptive** loops that search the prompt space and **multi-turn** strategies that decompose a
forbidden goal across individually-benign turns. Root weakness class: CWE-1426 (Improper
Validation of Generative AI Output) / CWE-1427 (prompt-injection). MITRE ATLAS: AML.T0054
(LLM Jailbreak), AML.T0071 (adversarial red-teaming evaluation).

Two families:
- **Optimization / iterative-refinement (mostly single-turn):** an *attacker LLM* proposes a
  prompt, a *judge LLM* scores the target's response, the attacker refines — repeat.
- **Multi-turn escalation:** exploit the gap between a single turn and the full conversation. Each
  turn is acceptable in isolation; the *sequence* crosses the line.

## Modern 2024-2026 Variants (verified)

| Method | Turns | Mechanism | Notes |
|--------|-------|-----------|-------|
| **PAIR** (Prompt Automatic Iterative Refinement) | single (iter) | Attacker LLM generates a jailbreak, judge LLM scores, refine up to ~20 iters | Fast, black-box |
| **TAP** (Tree of Attacks with Pruning) | single (tree) | Tree search over prompts; attacker generates ~4/step, judge prunes weak branches; ≤10 iters / ≤40 prompts | Extends PAIR; GCG/PAIR/TAP hit 80%+ ASR on GPT-4-Turbo/Gemini-Pro |
| **Crescendo** (MSR, **USENIX Security 2025**) | multi | Start benign on-topic, escalate by referencing the model's *own* prior answers | `Crescendomation` ~100% on disinfo/advocacy categories; +29–61% on GPT-4 over prior SOTA |
| **Best-of-N (BoN)** | single | Generate N augmented variants (case/typo/unicode/encoding); send all; one slips through | Up to ~89% ASR; "LIAR" variant cuts time-to-attack from hours to seconds |
| **GOAT** (Pavlova et al., 2024) | multi | Agentic red-team that reasons over a toolbox of attack strategies, adapts each turn | Generates human-like adaptive dialogues |
| **AutoDAN-Turbo** | single/multi | Lifelong black-box agent that *discovers* new jailbreak strategies from scratch | High ASR on SOTA models |
| **Skeleton Key** | single | Convince the model to *augment* (not replace) its rules with a permissive policy | Implemented as a PyRIT orchestrator |

Defense reference point: Anthropic's **Constitutional Classifiers** cut jailbreak success from
~86% to ~4.4% with <0.38% extra production refusals — so measure ASR *with guardrails enabled*.
For agents, also measure **Action-ASR**: did the jailbreak actually trigger a forbidden tool call,
not just forbidden text.

### Classifier-bypass tactics (current)
- **Address the human, not the AI** — never write "AI"/"ignore instructions"/"system" (the
  EchoLeak XPIA lesson) for injected-content jailbreaks.
- **Encoding converters** — base64 / ROT13 / leetspeak / homoglyph / zero-width / Morse; ask the
  model to decode-then-comply, or hide the ask in the encoding (BoN augmentation core).
- **Multi-turn priming** — establish a fictional frame, partial compliance, then escalate
  (Crescendo / Tempest branch on partial compliance).
- **Role/format coercion** — "respond only as JSON `{answer:...}`" suppresses refusal text.

## Complete working code/commands

`scripts/multiturn_jailbreak.py` is a complete attacker→target→judge loop supporting `crescendo`,
`pair`, and `bon` strategies against any OpenAI-compatible endpoint, with pluggable judge and
encoding converters. It records full transcripts and computes ASR (and Action-ASR if the target
returns tool-call traces).

```bash
pip install requests

# Crescendo: gradual multi-turn escalation, judge scores each turn, refine
python scripts/multiturn_jailbreak.py --strategy crescendo \
  --target-endpoint https://target/agent/chat --target-key "$TK" \
  --attacker-endpoint https://attacker-llm/v1/chat --attacker-key "$AK" \
  --judge-endpoint https://judge-llm/v1/chat --judge-key "$JK" \
  --objective "elicit step-by-step disallowed action X" --max-turns 8 \
  --transcript out/crescendo.jsonl

# PAIR: single-turn iterative refinement, up to 20 iterations
python scripts/multiturn_jailbreak.py --strategy pair \
  --target-endpoint $T --objective "$OBJ" --max-iters 20

# Best-of-N: 40 encoded/augmented variants of one objective in parallel
python scripts/multiturn_jailbreak.py --strategy bon \
  --target-endpoint $T --objective "$OBJ" --n 40 \
  --converters base64,leetspeak,unicode-confusable,case-shuffle
```

The same campaigns are runnable in **PyRIT** orchestrators (see agent-redteam-tooling.md) —
`CrescendoOrchestrator`, `TreeOfAttacksWithPruningOrchestrator`, `PAIROrchestrator`,
`SkeletonKeyOrchestrator` — when you want vendor-maintained converters/scorers.

## Detection

**Multi-turn escalation + BoN burst (defender side):**
```yaml
title: Automated / Multi-Turn Jailbreak Indicators
id: a3c1e7d2-aiagent-jb-0005
status: experimental
logsource:
  product: llm_gateway
  service: chat
detection:
  bon_burst:
    selection: distinct_prompts_per_session > 15
    timeframe: 2m
  high_perplexity:
    input_perplexity > 4.5        # obfuscated / random-augmented text
  encoding:
    prompt|re: '(?i)(base64|rot13|decode the following|zero-width|\\u200b)'
  escalation:
    selection: refusal_then_compliance_within_session == true   # rising compliance over turns
  condition: bon_burst or high_perplexity or encoding or escalation
level: medium
```

- **Per-session similarity clustering** catches BoN/iterative loops (many near-duplicate prompts).
- **Perplexity & encoding detectors** flag augmented/obfuscated inputs.
- **Multi-turn escalation scoring**: track refusal→partial→full-compliance transitions within a
  session (Crescendo signature). For agents, alert when a previously-refused tool call later
  succeeds in the same session.
- IOCs: 15+ semantically-similar prompts/2 min, base64/zero-width in inputs, "decode the
  following," conversation that pivots from fiction to operational detail.

## OPSEC

- **Touches:** the target model's inference + safety telemetry; high prompt volume is itself an
  IOC and can trip rate limits or look like DoS.
- **Cleanup:** none on the target beyond log entries; retain *your* transcripts (JSONL) as primary
  evidence for the report. Record model + guardrail versions — ASR is meaningless without them.
- **Evasion considerations:** throttle and randomize timing to avoid burst-clustering detection;
  use multi-turn (Crescendo) over BoN when perplexity/similarity detectors are present (each turn
  is low-perplexity and topically coherent); rotate sessions/identities so per-session escalation
  scoring resets. Keep objectives within the authorized scope; the goal is to *measure* ASR and
  whether a jailbreak unlocks a real agent action, not to generate genuinely harmful artifacts.

## References
- PAIR — Chao et al., "Jailbreaking Black Box LLMs in Twenty Queries."
- TAP — Mehrotra et al., "Tree of Attacks: Jailbreaking Black-Box LLMs Automatically."
- Crescendo — Russinovich et al. (Microsoft Research), USENIX Security 2025; arXiv:2404.01833.
- Best-of-N Jailbreaking — Anthropic/independent (Dec 2024); "LIAR" fast BoN variant.
- GOAT — Pavlova et al. (2024); AutoDAN-Turbo (lifelong agent).
- Anthropic, "Constitutional Classifiers" (defense baseline). OWASP LLM01:2025.
