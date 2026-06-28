# Breach, Infostealer & People OSINT

Cluster: harvesting identities (emails/usernames/people) and correlating them with breach databases
and infostealer logs to build an actionable credential-intelligence picture for initial access.
ATT&CK: T1589.001 (Gather Victim Identity Info: Credentials), T1589.002 (Email Addresses),
T1591 (Gather Victim Org Info), T1596 (Search Open Technical DBs). CWE-522 (Insufficiently Protected
Credentials), CWE-200.

## Theory / Mechanism

Two stages chained:

1. **Identity harvesting** — collect the org's email addresses, usernames, employee names, and
   email *format* (`first.last@`, `flast@`, `f.last@`) from public sources (search engines, PGP key
   servers, CT, social media, LinkedIn). Format derivation lets you generate the full employee
   address space from a roster of names.
2. **Exposure correlation** — query breach + infostealer corpora for those identities. Two
   fundamentally different data types:
   - **Breach databases** (HIBP, DeHashed): credentials dumped from a compromised *service*. Surface
     weeks/months after the incident.
   - **Infostealer logs**: passwords, cookies, and **session tokens** exfiltrated from an infected
     *endpoint* by malware (RedLine, Lumma, etc.). They appear in Telegram/shops within *hours* and
     are far more dangerous — they often contain *currently-valid* corporate creds and live session
     cookies that bypass passwords entirely.

The 2024 Snowflake intrusions are the canonical case: attackers used *aged* infostealer-log
credentials (no MFA) to breach 165 companies — old creds from years-old infections still worked.
Over half of 2024 ransomware victims had domains appear in stealer logs *before* the attack.

## Modern 2024-2026 Facts (verified)

- **theHarvester 4.x** aggregates ~43 sources into emails/subdomains/names/hosts; passive by design;
  uses PGP keyservers (finds addresses other scrapers miss); some sources (Shodan, Censys,
  SecurityTrails, GitHub) need API keys (BYOK), 50+ work without.
- **HIBP** holds 12B+ records from 929+ breached sites; **API v3** needs `hibp-api-key` header. In
  **Nov 2025** it ingested the **ALIEN TXTBASE** stealer-log dataset (~2B emails / 1.3B unique
  passwords). Free domain-search lets you list every exposed address on a domain you control/verify.
- **DeHashed** exposes the *underlying* breach data (usernames, plaintext/ hashed passwords, IPs,
  phone, address) and supports pivoting: leaked-password → reuse across accounts.
- **Be skeptical of headline dumps**: many "new" mega-breaches are recycled. The June-2025
  "16 billion password" story was mostly repackaged stealer logs. Validate by timestamp alignment,
  schema consistency, and cross-source agreement (HIBP ∩ DeHashed ∩ IntelX).
- Real-time infostealer monitoring platforms: **Flare**, **SpyCloud**, **Constella**, **IntelX**,
  **SOCRadar** (free tier searches 8,200+ combolists). These ingest Telegram/Tor/I2P channels.

## Complete Working Commands

### 1. Harvest identities + derive email format
```bash
DOMAIN=target.com
theHarvester -d $DOMAIN -b all -f harvester.json
jq -r '.emails[]?' harvester.json | sort -u > emails.txt
# Derive format from a real sample, then expand a name roster (first,last per line):
#   e.g. observed [email protected]  -> format = {f}{last}
python3 scripts/breach_intel.py --derive-format emails.txt --names roster.csv --domain $DOMAIN \
  > generated_emails.txt
# LinkedIn-style username generation (names -> flast/first.last/firstl) for spray/auth lists.
```

### 2. HIBP API v3 (breach + paste exposure)
```bash
EMAIL="[email protected]"
curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/$EMAIL?truncateResponse=false" \
  -H "hibp-api-key: $HIBP_API_KEY" -H "user-agent: recon-osint" | jq '.[] | {Name, BreachDate, DataClasses}'
# Domain-wide (you must verify ownership in HIBP first):
curl -s "https://haveibeenpwned.com/api/v3/breacheddomain/$DOMAIN" \
  -H "hibp-api-key: $HIBP_API_KEY" | jq '.'
# k-anonymity password check (never sends full hash):
SHA1=$(printf 'Password123' | sha1sum | tr 'a-z' 'A-Z' | cut -d' ' -f1)
curl -s "https://api.pwnedpasswords.com/range/${SHA1:0:5}" | grep -i "${SHA1:5}"
```

### 3. DeHashed (deep breach pivot — requires paid API)
```bash
curl -s "https://api.dehashed.com/search?query=domain:$DOMAIN" \
  -u "$DEHASHED_EMAIL:$DEHASHED_API_KEY" -H 'Accept: application/json' \
  | jq '.entries[] | {email, username, password, hashed_password, database_name}'
# Password-reuse pivot: take a recovered password, find every other account using it.
curl -s "https://api.dehashed.com/search?query=password:SuperSecret123" \
  -u "$DEHASHED_EMAIL:$DEHASHED_API_KEY" | jq '.entries[] | {email, database_name}'
```

### 4. Combined intel via this skill's tool
```bash
python3 scripts/breach_intel.py --domain $DOMAIN --harvest --hibp --dehashed \
  --emails emails.txt -o breach_out/
# Emits: breach_out/exposure.jsonl with {identity, source, breach, has_password, has_cookie, fresh}
```

## Password-Pattern & Spray-List Modeling

From recovered breach/stealer passwords, model the org's likely current patterns for password
spraying (feed `active-directory-attack` / `network-attack`):

```python
# Common derivations observed in real corp dumps:
#   {Company}{Year}{!|@|#}    Target2025!   Acme@2026
#   {Season}{Year}            Spring2026    Winter2025!
#   keyboard walks            Qwerty123!    1qaz@WSX
# Generate a conservative spray list (avoid lockout — 1-2 attempts/account/window):
for base in Target Acme Welcome Password; do
  for yr in 2025 2026; do for sym in '!' '@' '#'; do echo "${base}${yr}${sym}"; done; done
done
```

## Detection

Breach/infostealer *lookups* generate no telemetry on the target — they hit third-party APIs. The
defensive value is **monitoring**: an org should watch HIBP domain alerts / SpyCloud / Flare for its
own domains and *act before attackers do* (the timing window is the whole game with stealer logs).

```yaml
# Sigma — successful auth using a credential previously seen in a stealer log (identity provider)
title: Sign-in From Credential Present in Stealer-Log Feed
id: b71e0fa2-recon-stealer
status: experimental
logsource:
  product: azure
  service: signinlogs        # or Okta / Auth0 system log
detection:
  selection:
    ResultType: '0'          # success
  enrich_stealer_feed: true  # join UPN against ingested stealer-log/breach feed
  condition: selection and enrich_stealer_feed
fields: [UserPrincipalName, IPAddress, MfaDetail, AppDisplayName]
level: high
tags: [attack.t1078, attack.t1589.001]
```

IOCs (for the defender): sign-ins from creds present in stealer feeds, especially **without MFA**;
session reuse from a stolen cookie (same token, new IP/UA); impossible-travel after a domain shows up
in a fresh stealer dump.

## OPSEC

- **Touches:** nothing on the target — purely third-party API queries. The risk is *handling*, not
  detection.
- **Legal/PII:** breach + stealer data is sensitive personal data. Operate strictly within ROE;
  document a lawful basis; respect GDPR/CCPA. Store encrypted, minimize retention, never exfiltrate
  beyond engagement need.
- **Validation before use:** confirm a breach is real (timestamp/schema/cross-source) before acting
  on it — recycled dumps waste effort and can be planted. Tie every identity to a verified person/
  function/exposure path; mark unconfirmed links as such.
- **Spray discipline:** if you weaponize recovered patterns, throttle to avoid account lockout
  (1-2 attempts per account per lockout window) and coordinate with `active-directory-attack`.

## References

- laramies/theHarvester — https://github.com/laramies/theHarvester
- Have I Been Pwned API v3 + ALIEN TXTBASE (Nov 2025) — https://haveibeenpwned.com/API/v3 ; https://tools.osintnewsletter.com/osint-tools/have-i-been-pwned
- "Dark Web OSINT: Finding Your Leaked Data Before Criminals Do" (infostealer scale, Snowflake) — https://stateofsurveillance.org/articles/technical/dark-web-osint-leaked-data/
- infostealers-stats, "Credential-and-breach-monitoring" comparison — https://github.com/infostealers-stats/Credential-and-breach-monitoring/
- DeHashed — https://osintradar.com/tools/dehashed ; SOCradar OSINT guide — https://socradar.io/blog/osint-tools-for-cybersecurity-guide/
