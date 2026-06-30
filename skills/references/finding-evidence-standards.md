# Finding Evidence Standards (per CWE class)

What counts as **proof of real impact** for a finding, by vulnerability class. A finding
that cannot meet its class's bar is not "Low" — it is **not yet a finding**. This is the
human-readable contract behind `skills/vulnerability-analysis/scripts/validate_findings.py`
and is consumed by `commands/engage.gate.md` and the finding-validator review.

Rule of thumb: **a status code is not impact.** `200 OK`, a reflected string, or a DNS
callback proves *reachability*, not *exploitability*. Capture the thing an attacker
actually gains.

## Evidence bar by class

| Class (CWE) | CONFIRMED requires | NOT sufficient (downgrade/kill) |
|-------------|--------------------|---------------------------------|
| SSRF (CWE-918) | The internal/restricted **response body** read back (e.g. `169.254.169.254` metadata, internal service contents) | A bare DNS/OOB pingback with no response read |
| IDOR / BOLA (CWE-639/862) | **Another principal's** data returned, using a second identity you control to prove it isn't your own | Changing an `id` and still getting *your own* object (self-IDOR); a `200` with no cross-identity data |
| Broken auth (CWE-287/306) | Access to a protected action/resource **without valid credentials** | A login page loading; a 401 you "expect" to bypass |
| CORS misconfig (CWE-942) | Reflected `ACAO` **and** `Access-Control-Allow-Credentials: true`, plus a cross-origin read of authenticated data | `ACAO: *` on a public, unauthenticated endpoint; reflection without credentials |
| Open redirect (CWE-601) | Redirect to an **external/attacker-controlled** origin | Same-origin or relative redirect |
| XSS (CWE-79) | Script **execution** demonstrated (alert/console/DOM mutation/exfil), in the victim context | Reflection of the payload that is HTML-encoded/escaped, "not executed" |
| SQLi (CWE-89) | Data extracted, boolean/time oracle confirmed, or DBMS error proving injection | A WAF block page; a generic 500 |
| RCE / command injection (CWE-77/78/94) | **Command output** (`uid=`, `whoami`, file contents) or an OOB callback that proves execution | A crash/DoS; "blind" with no confirming signal |
| Insecure deserialization (CWE-502) | Demonstrated code/command execution or object instantiation with effect | Reaching the sink with no observable effect |
| Path traversal (CWE-22) | Contents of a file **outside** the intended directory | A `404`/`403` on `../`; reading an in-directory file |
| Secrets exposure (CWE-200/798) | A **live, valid** secret demonstrated to authenticate, or sensitive data returned | A high-entropy string that is expired/test/placeholder |
| Privilege escalation (CWE-269) | A shell/token **as the target principal** (root/SYSTEM/admin) | A technique that "should" work; a writable file with no exploitation |
| Race condition / TOCTOU (CWE-362/367) | The double-spend / limit-bypass **outcome** observed (e.g. 2 redemptions of a 1-use code) | Two requests returning `200` with no state effect |

## Severity discipline

- Rank by **CVSS / real impact**, never by "how cool" or by bug-bounty payout.
- A confirmed-but-low-impact issue is `Low`/`Info` — keep it, but do not inflate it.
- Severity claimed must be supported by the evidence (an IDOR exposing only a display name
  is not `Critical`).

### CVSS inherent-impact rule (native memory-corruption)

A confirmed, *attacker-controllable* memory corruption (controlled write, UAF with a reclaimed
object, OOB write past a guard) carries an **inherent impact ceiling** — usually code execution —
that exists whether or not you have finished the exploit. Do not cap such a finding at "DoS / crash"
merely because the only artifact so far is a SIGSEGV. **But** the ceiling is claimed only with two
things attached, so this refines — never overrides — the "no inflation / a status code is not impact"
rule above:

1. A **feasibility verdict** (`true` / `false` / `null`) from `finding-validation-runtime.md`. The
   inherent ceiling is asserted only when feasibility is `true`; on `null` the finding stays
   `[POSSIBLE]` at the *demonstrated* severity with the ceiling noted as the open question.
2. Both numbers recorded explicitly: **`demonstrated`** (what the current PoC actually shows) and
   **`inherent`** (the class ceiling, gated by the feasibility verdict). Never silently report the
   ceiling as if it were demonstrated.

So a controllable heap overflow with `feasibility:true` is scored on its code-exec ceiling even before
a full chain; the same crash with `feasibility:null` is `[POSSIBLE]`, demonstrated=DoS, inherent=RCE
(open). The corruption being controllable is itself an evidence claim — back it, do not assume it from
the crash address.

## Do-not-report list (these are not findings on their own)

- Version banners / fingerprinting, missing security headers with no demonstrated impact,
  cookie flags with no session-theft path, autocomplete-on, verbose 404s.
- Self-XSS, self-IDOR, CSRF on unauthenticated or stateless endpoints, logout CSRF.
- "Reflected but encoded" inputs, `ACAO: *` on public data, same-origin "open redirects".
- Theoretical/`should-be-vulnerable` claims with no reproduction.
- Out-of-scope assets (the finding is void regardless of severity — see `scope_guard.py`).

Promote these only when **chained** into a class above with demonstrated impact (record the
chain — see `finding-validation-runtime.md`).
