# Terms of Use & Acceptable Use Policy

`offensive-claude` is an **offensive security framework** for authorized red-team
operations, penetration testing, vulnerability research, CTFs, and security education.
It generates real attack tooling, payloads, and exploitation guidance. Using it against
systems you are not explicitly authorized to test is illegal and harmful. By using this
project you agree to the following.

## 1. Authorization is mandatory

You may only use this toolkit against assets for which you hold **prior, written
authorization** that explicitly covers the activities you perform — e.g. a signed
penetration-testing agreement / statement of work, a bug-bounty program's published
scope and safe-harbor, your own lab/property, or a sanctioned CTF.

- Record that authorization before Phase 0 and encode the boundary in a machine-readable
  `scope.json` (see `templates/scope/scope.schema.json`). The `scope_guard.py` tool exists
  so "stay in scope" is *enforced*, not merely promised.
- Out-of-scope assets, shared/third-party infrastructure, and anything not named in your
  authorization are off-limits.

## 2. You are responsible for every action

This is a tool. **You own every request, payload, and command it helps you send.**
"The AI did it," "the script ran automatically," or "it was in the workflow" are **not**
legal or ethical defenses. You are the operator and the responsible party.

## 3. Prohibited uses

Do **not** use this project to:

- Access, attack, disrupt, or exfiltrate data from systems without authorization.
- Conduct denial-of-service / resource-exhaustion attacks unless explicitly permitted in
  writing by the asset owner.
- Deploy ransomware, destructive payloads, or persistence on systems you do not own or
  are not authorized to modify.
- Target individuals, harvest personal data, or conduct surveillance outside an authorized
  and lawful engagement.
- Violate any applicable law, including but not limited to the U.S. **Computer Fraud and
  Abuse Act (CFAA)**, the U.K. **Computer Misuse Act**, the EU directives on attacks against
  information systems, or your local equivalents.

## 4. Data handling

Handle any data encountered during an engagement per your contract and applicable law:
minimize collection, protect it in transit and at rest, and dispose of it when the
engagement ends. Never collect more than the engagement requires.

## 5. Responsible disclosure

Report vulnerabilities you discover to the asset owner through the agreed channel. Do not
publicly disclose, sell, or weaponize findings outside the engagement's terms. For issues
in *this project itself*, see [`.github/SECURITY.md`](.github/SECURITY.md).

## 6. No warranty

This project is provided "as is", without warranty of any kind, under the terms of its
[LICENSE](LICENSE). The authors and contributors are not liable for any misuse or for any
damage arising from its use.

---

**If you do not have explicit authorization for what you are about to do, stop.**
