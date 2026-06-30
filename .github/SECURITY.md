# Security Policy

This policy covers vulnerabilities in **this project's own code** — the helper scripts,
`install.sh` / `install_tools.sh`, templates, and tooling shipped in this repository.

It does **not** cover third-party systems you test *with* the toolkit. Findings against
external targets belong to that target's owner and their disclosure process, governed by
your engagement authorization and [`TERMS.md`](../TERMS.md) — do not report those here.

## Reporting a vulnerability in offensive-claude

If you find a security issue in this repository's code (e.g. a command-injection bug in a
helper script, an unsafe default in `install.sh`, a scope-guard bypass in
`scope_guard.py`, or a credential-handling flaw):

1. **Do not** open a public issue for it.
2. Report privately via **GitHub Security Advisories** ("Report a vulnerability" on the
   repo's *Security* tab), or contact the maintainer listed in the repository profile.
3. Include: affected file/version, impact, and minimal reproduction steps.

We aim to acknowledge reports within a few days and to fix confirmed issues promptly.
Coordinated disclosure is appreciated — please give us a reasonable window before any
public write-up.

## Scope-guard / safety-control reports get priority

Because this is offensive tooling, bugs that **weaken a safety control** are treated as
high severity, for example:

- a `scope_guard.py` matching flaw that lets an out-of-scope host be classified in-scope,
- a `validate_findings.py` bug that passes an ungrounded/false-positive finding,
- a `safe_subprocess.py` flaw that lets a shell string through, leaks the parent environment
  to a child, or runs git against an untrusted repo without the hook/prompt/config hardening,
- credential leakage from `http_creds.py` or any script logging a secret in clear text.

Please flag these explicitly so we can prioritize them.

## Out of scope for this policy

- Vulnerabilities in third-party tools the framework *invokes* (nmap, ffuf, impacket, etc.)
  — report those upstream.
- Findings produced by *using* the framework against your engagement targets.
