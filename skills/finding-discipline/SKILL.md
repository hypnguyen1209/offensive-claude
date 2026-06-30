---
name: finding-discipline
description: Use when about to record, claim, rate the severity of, or report any security finding — before marking anything [CONFIRMED] or writing it into the report
---

# Finding Discipline

## Overview

**The Iron Law: No `[CONFIRMED]` without proof.** A finding is a claim about real, demonstrated
impact — not a status code, a reflected string, or a hunch. This is the offensive equivalent of
test-driven development: the proof is the test, and the finding does not exist until it passes.

**Violating the letter of this rule is violating its spirit.**

## The three tiers

- **`[CONFIRMED]`** — impact demonstrated AND grounded in an evidence artifact that exists on disk.
- **`[POSSIBLE]`** — reachable but the class proof bar is not yet met. Keep digging; do not report as real.
- **`[INFO]`** — true but no security impact at the claimed severity.

## The proof bar (per class)

A status code is not impact. See `skills/references/finding-evidence-standards.md`:
SSRF needs the internal response; IDOR needs *another principal's* data; RCE needs command output;
XSS needs script execution; open redirect needs an external destination.

## Required mechanical gate

Before any finding is recorded or reported:

1. Set the structured proof signal and run
   `python skills/vulnerability-analysis/scripts/validate_findings.py --findings f.json --evidence ./evidence`
   — it rejects ungrounded findings and per-class false positives.
2. Pass it through the **REQUIRED** `finding-validator` agent (PASS / KILL / DOWNGRADE).
3. Only a `[CONFIRMED]` survivor goes in the report. Severity must match what was demonstrated (CVSS honest).

See `skills/references/finding-validation-runtime.md` for the 7-question gate.

## Read-first, never name-guess

If a function calls another, **read the callee** — do not infer what it does from its name.
`sanitize()`, `is_safe()`, `validate_input()` are exactly where vulnerabilities hide; a name is a
claim by the author, not evidence. The same applies to a config key, a decorator, or a CVE title:
open the thing before you reason about it. An unread dependency in a data-flow claim is a hole.

## Quote-grounded confidence tiers

Every claim in a finding carries a confidence grounded in *what you can quote*, not in how it feels:

- **High** — a **direct quote** from the artifact (the exact source line, the response body, the
  decompiled instruction) supports the claim.
- **Medium** — an **explicitly stated assumption** bridges a gap you could not directly observe.
  State the assumption; do not hide it.
- **Low** — an **inference** you are flagging as unverified. Acceptable to record, never to report as
  fact.

This is orthogonal to the `[CONFIRMED]/[POSSIBLE]/[INFO]` tier (which is about *impact*); confidence
is about *how well-grounded the claim is*. A High-confidence claim of a Low-impact bug is still Low.

## Red Flags — STOP, downgrade to `[POSSIBLE]`

- "I'm sure it's exploitable" (but haven't shown impact)
- "The payload reflected, so it's XSS" / "I got a 200, so it works"
- "The DNS callback fired" (SSRF with no internal response)
- "I changed the id and got data" (but it was my own — self-IDOR)
- "It probably works on a real target" (default-deployment unproven)

**All of these mean: it is `[POSSIBLE]`, not `[CONFIRMED]`. Get the evidence.**

## Rationalizations

| Excuse | Reality |
|--------|---------|
| "Pattern-matched, clearly vulnerable" | Pattern ≠ exploit. Demonstrate impact or it's POSSIBLE. |
| "I'll attach evidence later" | No artifact on disk = ungrounded = REJECTED now. |
| "Blind RCE counts" | No output / no OOB confirmation = POSSIBLE, not CONFIRMED. |
| "Severity is obviously Critical" | CVSS must reflect demonstrated impact, not the worst case. |
| "The validator is overkill here" | Untested findings are how false positives ship. Run it. |
| "The function is called `sanitize`, so it's safe" | A name is the author's claim, not proof. Read the callee. |
| "The solver timed out, so it's not exploitable" | A tool limit is `feasibility:null` (manual), never `false`. |

A short list of CONFIRMED findings beats a long list of POSSIBLEs. Killing a false positive is success.
