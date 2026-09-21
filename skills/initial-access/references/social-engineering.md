# Social Engineering — the human layer

Attacking people, not just their mail gateway. This complements the phishing/payload-delivery in
`SKILL.md` (the technical SE) with the human-layer tradecraft a full red-team engagement uses: pretext
design, voice (vishing), SMS (smishing), and help-desk / MFA social attacks. Physical vectors
(tailgating, badge cloning, USB drops) live in the SKILL's "Advanced: Physical Access Vectors" section.

> **AUTHORIZATION IS NOT OPTIONAL HERE.** Human-layer SE targets employees, contractors, and third
> parties — people who did not sign your ROE. Before ANY pretext contact: (1) explicit **written**
> authorization that names social engineering and the **allowed channels/targets** (many engagements
> exclude vishing, or exclude certain departments/individuals); (2) a **legal review** — recording calls,
> impersonating staff/vendors, and pretexting are regulated differently by jurisdiction (two-party
> consent, impersonation statutes); (3) a **no-harm rule** — never induce an action that damages the
> person or a real third party, never collect more than the engagement needs, and have an immediate
> **stand-down / disclosure** procedure. Confirm scope with `scope-discipline`; state OPSEC before contact
> with `opsec-discipline`. Authorized engagements only (`TERMS.md`).

## Pretexting — the scenario is the exploit

A pretext is a believable reason for the target to do what you want. It is built from recon, not
invented. Feed `recon-osint` output (org chart, vendors, tooling, tone, current events, LinkedIn roles)
into a scenario the target has a reason to believe.

- **Sourcing:** who reports to whom, which IT/help-desk/HR/payroll tools are in use, active projects,
  vendor relationships, employee names + role + email format, out-of-office/travel signals.
- **Strong pretexts (2024-2026):** IT/help-desk "we're rolling out MFA / your account is locked",
  a known SaaS vendor "security alert", finance/AP invoice or payroll-change, recruiter/opportunity,
  internal survey/benefits. The best pretext creates **mild time pressure + a plausible authority**.
- **Consistency:** caller-ID/sender/domain, jargon, ticket numbers, and a callback path must all agree —
  one inconsistency breaks it. ATT&CK **T1598** (phishing for information), **T1591** (gather org info).

## Vishing (voice) & callback phishing / TOAD

- **Vishing:** a phone pretext (help-desk, vendor support, exec assistant) to extract info, trigger an
  action (reset a password, approve a request), or walk a target through installing a "tool". Spoofed
  caller-ID + a matching internal ticket number is the common force-multiplier.
- **Callback phishing (TOAD — Telephone-Oriented Attack Delivery):** an email with **no link/attachment**
  (evades URL/attachment scanning) that asks the target to **call a number** ("renewal charge, call to
  cancel"); the call then drives remote-tool install or credential capture. High deliverability precisely
  because there's nothing for the gateway to detonate. ATT&CK **T1566** / **T1598**.
- **Detection/telemetry:** helpdesk/callback anomalies, spikes in password-reset or MFA-reset tickets,
  remote-tool installs (AnyDesk/Quick Assist/TeamViewer) right after an inbound call, caller-ID/ANI
  mismatch. **OPSEC/care:** call recording may be illegal without consent; keep a per-call log; never
  leave the target worse off; stand down if the person is distressed.

## Smishing (SMS) & messaging

Short, urgent SMS/WhatsApp/Teams/Slack pretext with a link or a callback ask (MFA code request, delivery
notice, exec impersonation "are you at your desk?"). Mobile context strips the desktop's visual trust
cues. ATT&CK **T1566.002** (spearphishing link). Detection: URL-shortener + new-domain + off-hours to
many employees; brand-impersonation domains.

## Help-desk & MFA social attacks (the high-impact modern path)

The tradecraft behind several 2023-2025 intrusions: **socially engineer the IT help desk** into resetting
a password or **re-enrolling an attacker's MFA device**, or wear the target down with **MFA push-bombing**
then call posing as IT to "help stop the prompts" (getting them to approve one).

- **Help-desk reset abuse:** impersonate an employee (armed with OSINT identity data) to get a credential
  or MFA reset — bypasses a strong password entirely. ATT&CK **T1556** / **T1078** (valid accounts).
- **MFA fatigue / push bombing:** repeated push approvals until the user accepts. ATT&CK **T1621** (MFA
  request generation). Chains into the vishing "IT will help you stop it" script.
- **Evidence bar (finding-discipline):** a pretext that got a *reset/enrollment/approval* and a resulting
  **authenticated session/foothold** is `[CONFIRMED]`; "the target seemed receptive" is not impact.
- **Defense to report:** help-desk identity-proofing (call-back to a known number, manager verification,
  no reset-over-phone), number-matching / phishing-resistant MFA (FIDO2), push-fatigue rate limits.

## OPSEC & detection summary

| Vector | Detection signal | OPSEC / legal note |
|--------|------------------|--------------------|
| Pretext email/DM | new/look-alike domain, urgency + authority, reply-to mismatch | keep pretext infra scoped; retire it post-engagement |
| Vishing / TOAD | callback-number email w/ no URL; remote-tool install post-call; ANI mismatch | recording-consent laws; per-call log; immediate stand-down |
| Smishing | shortener + new domain to many staff off-hours | sending SMS at scale may need a compliant provider; stay in scope |
| Help-desk / MFA | reset/enroll spikes; push-bomb bursts; approval after inbound "IT" call | only named targets; never lock a real user out; disclose on completion |

## Cross-references

- **Phishing / payload delivery / HTML smuggling / physical vectors →** this skill's `SKILL.md`.
- **Pretext sourcing (org/people/tooling OSINT) →** `recon-osint`. **Scope + authorization →**
  `scope-discipline`; **detection-aware conduct →** `opsec-discipline`; **proof bar →** `finding-discipline`.
