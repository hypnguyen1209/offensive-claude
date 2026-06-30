# Runtime Finding Validation (the exploitability gate)

The dynamic-testing counterpart to `taint-false-positive-reduction.md` (which covers
static source audit). Apply this BEFORE a live/dynamic finding is recorded or reported.
Operationalized by `skills/vulnerability-analysis/scripts/validate_findings.py`; the
per-class proof bar lives in `finding-evidence-standards.md`.

A finding passes only if it survives all seven questions. Default verdict on doubt is
**downgrade**, not promote.

## The 7-question gate

1. **In scope?** Is the affected host in `scope.json`? Run
   `scope_guard.py check <target> --scope scope.json`. Out-of-scope ⇒ the finding is void
   (delete it), regardless of severity.
2. **Grounded?** Does every claim point at a real evidence artifact (request/response,
   log, screenshot) that exists on disk? An ungrounded claim is `REJECTED`.
2.5. **Authentic at source?** If a claim leans on an *external* source (a CVE entry, a vendor
   advisory, a GitHub commit/PR, a third-party writeup), is that source re-verifiable — captured
   with its URL **and** a content hash so it can be re-fetched and re-checked? "Authentic and still
   true at source" is a separate question from "does the claim follow"; collapsing them lets a stale
   or fabricated source URL slip through. An external source that cannot be re-verified ⇒
   **downgrade**, never silent acceptance. (Local first-party evidence from question 2 is exempt;
   PR-2's `evidence_kit.py` mechanizes the hash/re-fetch.)
3. **Reachable?** Did *your input* actually reach the sink/behavior (not a WAF page, not a
   default error)?
4. **Controllable?** Do you control the part that matters (the redirect target, the object
   id, the injected token), or is it fixed/sanitized?
5. **Impactful?** Does the evidence meet the **class bar** in `finding-evidence-standards.md`?
   (SSRF → internal response; IDOR → another principal's data; RCE → command output; …)
6. **Default deployment?** Does it work on a stock install, or only with a non-default
   misconfiguration the customer didn't ship? Note the precondition; it caps severity.
7. **Severity honest?** Is the CVSS vector supported by what you actually demonstrated —
   no inflation?

## Verdicts

- **CONFIRMED** — passes 1–7; class bar met. Record with full evidence + CVSS + ATT&CK + CWE.
- **POSSIBLE** — grounded and reachable but the class bar isn't met yet (e.g. blind RCE with
  no output, CORS reflection without `ACAC:true`). Keep investigating; do not report as-is.
- **INFO** — real but no security impact at current severity (record as hardening note).
- **REJECTED** — out of scope, ungrounded, or hit a kill-signal (self-IDOR, same-origin
  "redirect", encoded "XSS", DNS-only "SSRF"). Drop it.
- **CHAIN-REQUIRED** — individually `Info`/`Low`, but promotes when combined with another
  finding. Only valid if you record the *complete* chain and demonstrate the end impact.

## The feasibility verdict ladder (native / exploit findings)

For memory-corruption and exploit-class findings, "reachable" is not the same as "exploitable". Carry
an explicit **feasibility** verdict alongside the tier — and treat *unknown* as a first-class value,
never as a kill:

| `feasibility` | Meaning | What it does to the finding |
|---------------|---------|-----------------------------|
| `true` | Exploitability demonstrated/proven for the claimed primitive (PoC, controlled corruption, satisfiable path) | Supports the inherent-impact severity (see `finding-evidence-standards.md`) |
| `false` | Proven NOT exploitable as claimed (e.g. a solver shows the path is unsatisfiable, or the mitigation set blocks it) | DOWNGRADE/REJECT the exploit claim; the crash may still be a DoS-only finding |
| `null` | Unknown — the tool/solver hit a limit, timed out, or the analysis is incomplete | **Falls through to manual analysis. NEVER auto-kills.** Record it as `[POSSIBLE]` with the open question, do not round to `false` |

The cardinal rule: **a solver/coverage/timeout limit is `null`, not `false`.** Tools refute paths;
they do not get to silently kill a finding because they ran out of budget. Only positive evidence of
non-exploitability is `false`. (The empirical mitigation-matrix and SMT path-prune that *produce*
these verdicts land in PR-3 / PR-2; this gate states how to record them.)

## The identity test (IDOR vs. "missing auth" vs. self-IDOR)

Use **two accounts you control** (victim `V`, attacker `A`):

- Request `V`'s object as `A`. If `A` gets `V`'s data ⇒ **IDOR/BOLA** (CONFIRMED).
- If the object is reachable **with no session at all** ⇒ that's **broken auth / missing
  access control** (CWE-306/862), classify it as such — not IDOR.
- If "the other id" is really still `A`'s own object ⇒ **self-IDOR** ⇒ REJECTED.

## Structured proof signals (what the harness checks)

`validate_findings.py` is mechanical: it does **not** parse prose (prose is paraphrasable
in both directions). It reads a `proof` object of explicit booleans. CONFIRMED requires the
class's positive signal to be `true`; a disqualifier signal forces REJECTED; otherwise the
finding is POSSIBLE. Set these honestly — the adversarial finding-validator agent / human
review judges whether the boolean is *true*, and the evidence must back it.

| Class (CWE) | `proof.<confirm>` = true to CONFIRM | `proof.<disqualify>` = true ⇒ REJECTED |
|-------------|-------------------------------------|-----------------------------------------|
| SSRF (918) | `internal_response_read` | — (no signal ⇒ POSSIBLE: DNS-only callback) |
| IDOR/BOLA (639/862) | `cross_identity_confirmed` | `self_idor` |
| CORS (942) | `creds_reflected_origin` | — |
| Open redirect (601) | `external_redirect` | `same_origin` |
| XSS (79/80) | `script_executed` | `encoded_inert` |
| RCE / cmd / deser (78/77/94/502) | `command_output_captured` | — (blind/no output ⇒ POSSIBLE) |

Example finding (one entry of the `--findings` JSON list):

```json
{"id":"FIND-014","title":"SSRF in webhook fetch","cwe":"CWE-918","severity":"High",
 "evidence":["logs/FIND-014.txt"], "proof":{"internal_response_read": true}}
```

A finding with no structured proof, or only prose, can never tier above **POSSIBLE** for a
recognized class — by design. When in doubt, downgrade and gather the missing evidence; a
smaller list of CONFIRMED findings beats a long list of POSSIBLEs every time.
