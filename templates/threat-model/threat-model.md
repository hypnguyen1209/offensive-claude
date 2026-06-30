---
phase: recon
status: draft
gate: [threat_model_complete, no_unreviewed_drift]
produces: [threat-model.json]
---

# Threat Model

Materialized from recon-osint. Keep the machine-readable `threat-model.json` in sync — the gate lints
it and diffs it for drift (`skills/threat-model-discipline/scripts/threatmodel_lint.py`).

## Assets (what an attacker wants)
- [e.g. customer PII in the orders DB]
- [admin session tokens]

## Entry Points (where untrusted input enters)
- [e.g. POST /api/login (unauthenticated)]
- [file upload at /api/avatar]

## Trust Boundaries (where privilege/trust changes)
- [internet → web tier]
- [web tier → internal metadata service]

## ATT&CK Techniques (what you will test for)
- T1190 (Exploit Public-Facing Application)
- T1078 (Valid Accounts)

## Mitigations (controls already present)
- [WAF in front of /api]
- [output encoding in the template layer]

## Machine-readable form (`threat-model.json`)

```json
{
  "assets": ["customer PII in orders DB", "admin session tokens"],
  "entry_points": ["POST /api/login", "POST /api/avatar"],
  "trust_boundaries": ["internet->web tier", "web tier->metadata service"],
  "attck": ["T1190", "T1078"],
  "mitigations": ["WAF on /api", "output encoding in templates"]
}
```

Save the baseline after review (`threat-model.baseline.json`); re-run recon → regenerate
`threat-model.json` → `threatmodel_lint.py drift baseline new` to catch new unreviewed surface.
