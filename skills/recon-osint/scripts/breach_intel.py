#!/usr/bin/env python3
"""
breach_intel.py — Identity harvesting + breach/infostealer credential correlation.

Modules:
  --derive-format : infer the org email format from observed samples, expand a name roster.
  --harvest       : shell out to theHarvester (passive) for emails/hosts/names.
  --hibp          : Have I Been Pwned API v3 (breaches + pastes) per email; k-anonymity password chk.
  --dehashed      : DeHashed deep breach pivot (requires paid API creds).

USAGE:
  python3 breach_intel.py --domain target.com --harvest --hibp --dehashed -o breach_out/
  python3 breach_intel.py --derive-format emails.txt --names roster.csv --domain target.com

ENV / KEYS:
  HIBP_API_KEY               (api v3 header 'hibp-api-key')
  DEHASHED_EMAIL, DEHASHED_API_KEY   (HTTP basic auth)

DEPENDENCIES:  pip install requests ; theHarvester on PATH for --harvest

OUTPUT:
  breach_out/exposure.jsonl   {identity, source, breach, date, dataclasses, has_password, fresh}
  breach_out/generated_emails.txt (when --names given)

LEGAL/OPSEC: queries hit ONLY third-party APIs (no target telemetry). Breach + infostealer data are
sensitive PII — operate within ROE, document lawful basis, store encrypted, minimize retention.
Validate dumps (timestamp/schema/cross-source) before acting; many "new" dumps are recycled.

Authorized engagements only.
"""
import argparse
import csv
import json
import os
import re
import subprocess
import sys
import time
from hashlib import sha1

try:
    import requests
except ImportError:
    print("[!] pip install requests", file=sys.stderr)
    raise

UA = "recon-osint-breach-intel"

# Email-format tokens we can derive: {first},{last},{f},{l},{first}.{last},{f}{last}, etc.
FORMAT_PATTERNS = [
    ("{first}.{last}", lambda f, l: f"{f}.{l}"),
    ("{f}{last}",      lambda f, l: f"{f[0]}{l}"),
    ("{first}{last}",  lambda f, l: f"{f}{l}"),
    ("{f}.{last}",     lambda f, l: f"{f[0]}.{l}"),
    ("{first}{l}",     lambda f, l: f"{f}{l[0]}"),
    ("{first}_{last}", lambda f, l: f"{f}_{l}"),
    ("{last}{f}",      lambda f, l: f"{l}{f[0]}"),
    ("{first}",        lambda f, l: f"{f}"),
]


def derive_format(emails_file, domain):
    """Guess the dominant local-part format from sample emails. Returns the best pattern label+fn."""
    locals_ = []
    for line in open(emails_file, encoding="utf-8", errors="replace"):
        line = line.strip().lower()
        if "@" in line and line.endswith(domain.lower()):
            locals_.append(line.split("@")[0])
    if not locals_:
        return None
    # Heuristic: dotted -> {first}.{last}; else if short -> {f}{last}; else {first}{last}.
    dotted = sum(1 for x in locals_ if "." in x)
    if dotted > len(locals_) / 2:
        return FORMAT_PATTERNS[0]
    avg = sum(len(x) for x in locals_) / len(locals_)
    return FORMAT_PATTERNS[1] if avg <= 8 else FORMAT_PATTERNS[2]


def expand_roster(names_csv, domain, fmt):
    """names_csv: 'first,last' per line. Returns generated emails."""
    label, fn = fmt
    out = []
    with open(names_csv, encoding="utf-8", errors="replace") as fh:
        for row in csv.reader(fh):
            if len(row) < 2:
                continue
            first = re.sub(r"[^a-z]", "", row[0].strip().lower())
            last = re.sub(r"[^a-z]", "", row[1].strip().lower())
            if first and last:
                out.append(f"{fn(first, last)}@{domain}")
    return sorted(set(out)), label


def harvest(domain, out):
    if not any(os.path.exists(os.path.join(p, "theHarvester"))
               for p in os.environ.get("PATH", "").split(os.pathsep)) and \
       not subprocess.run(["bash", "-lc", "command -v theHarvester"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
        print("[!] theHarvester not found — skipping --harvest", file=sys.stderr)
        return []
    jf = os.path.join(out, "harvester")
    subprocess.run(["theHarvester", "-d", domain, "-b", "all", "-f", jf],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    emails = []
    jpath = jf + ".json"
    if os.path.exists(jpath):
        try:
            data = json.load(open(jpath, encoding="utf-8", errors="replace"))
            emails = sorted(set(data.get("emails", [])))
        except (json.JSONDecodeError, OSError):
            pass
    print(f"[+] theHarvester emails: {len(emails)}", file=sys.stderr)
    return emails


def hibp_account(email, key):
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    try:
        r = requests.get(url, params={"truncateResponse": "false"},
                         headers={"hibp-api-key": key, "user-agent": UA}, timeout=15)
    except requests.RequestException:
        return []
    if r.status_code == 404:
        return []           # not pwned
    if r.status_code == 429:
        time.sleep(2)
        return hibp_account(email, key)
    if r.status_code != 200:
        return []
    recs = []
    for b in r.json():
        dc = b.get("DataClasses", [])
        recs.append({
            "identity": email, "source": "hibp", "breach": b.get("Name"),
            "date": b.get("BreachDate"), "dataclasses": dc,
            "has_password": any("password" in d.lower() for d in dc),
            # ALIEN TXTBASE / "Stealer Logs" tagged breaches = fresh infostealer-origin
            "fresh": bool(b.get("IsStealerLog")) or "Stealer" in (b.get("Name") or ""),
        })
    return recs


def hibp_password_pwned(password, _key=None):
    """k-anonymity range check — only the first 5 SHA1 chars leave the host."""
    h = sha1(password.encode()).hexdigest().upper()
    prefix, suffix = h[:5], h[5:]
    try:
        r = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}",
                         headers={"user-agent": UA}, timeout=10)
    except requests.RequestException:
        return 0
    for line in r.text.splitlines():
        s, _, count = line.partition(":")
        if s == suffix:
            return int(count)
    return 0


def dehashed(domain, email_user, api_key):
    try:
        r = requests.get("https://api.dehashed.com/search",
                         params={"query": f"domain:{domain}", "size": 10000},
                         auth=(email_user, api_key),
                         headers={"Accept": "application/json", "user-agent": UA}, timeout=30)
    except requests.RequestException:
        return []
    if r.status_code != 200:
        print(f"[!] dehashed http {r.status_code}", file=sys.stderr)
        return []
    recs = []
    for e in (r.json().get("entries") or []):
        recs.append({
            "identity": e.get("email") or e.get("username"), "source": "dehashed",
            "breach": e.get("database_name"), "date": None,
            "dataclasses": [k for k in ("password", "hashed_password", "phone", "address") if e.get(k)],
            "has_password": bool(e.get("password") or e.get("hashed_password")),
            "fresh": "stealer" in (e.get("database_name") or "").lower(),
        })
    return recs


def main():
    ap = argparse.ArgumentParser(description="Breach / infostealer / people OSINT")
    ap.add_argument("--domain", required=True)
    ap.add_argument("--emails", help="pre-existing email list to enrich")
    ap.add_argument("--names", help="roster CSV (first,last) to expand via derived format")
    ap.add_argument("--derive-format", dest="derive", help="sample emails file to infer format")
    ap.add_argument("--harvest", action="store_true")
    ap.add_argument("--hibp", action="store_true")
    ap.add_argument("--dehashed", action="store_true")
    ap.add_argument("-o", "--out", default="breach_out")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    emails = set()
    if args.emails and os.path.exists(args.emails):
        emails |= {e.strip().lower() for e in open(args.emails, encoding="utf-8", errors="replace")
                   if "@" in e}

    # Format derivation + roster expansion
    if args.names:
        src = args.derive or args.emails
        fmt = derive_format(src, args.domain) if src else FORMAT_PATTERNS[0]
        if fmt is None:
            fmt = FORMAT_PATTERNS[0]
        gen, label = expand_roster(args.names, args.domain, fmt)
        with open(os.path.join(args.out, "generated_emails.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(gen) + "\n")
        emails |= set(gen)
        print(f"[+] format='{label}' generated {len(gen)} emails", file=sys.stderr)

    if args.harvest:
        emails |= set(harvest(args.domain, args.out))

    expo_path = os.path.join(args.out, "exposure.jsonl")
    written = 0
    with open(expo_path, "w", encoding="utf-8") as out:
        if args.hibp:
            key = os.environ.get("HIBP_API_KEY")
            if not key:
                print("[!] HIBP_API_KEY not set — skipping HIBP account lookups", file=sys.stderr)
            else:
                for em in sorted(emails):
                    for rec in hibp_account(em, key):
                        out.write(json.dumps(rec) + "\n")
                        written += 1
                    time.sleep(1.6)   # respect HIBP rate limit (per-key)
        if args.dehashed:
            du, dk = os.environ.get("DEHASHED_EMAIL"), os.environ.get("DEHASHED_API_KEY")
            if not (du and dk):
                print("[!] DEHASHED_EMAIL/DEHASHED_API_KEY not set — skipping", file=sys.stderr)
            else:
                for rec in dehashed(args.domain, du, dk):
                    out.write(json.dumps(rec) + "\n")
                    written += 1

    print(f"[+] exposure records: {written} -> {expo_path}", file=sys.stderr)
    fresh = 0
    if os.path.exists(expo_path):
        for line in open(expo_path, encoding="utf-8", errors="replace"):
            try:
                if json.loads(line).get("fresh"):
                    fresh += 1
            except json.JSONDecodeError:
                pass
    if fresh:
        print(f"[!] {fresh} records flagged FRESH (infostealer/stealer-log origin) — "
              f"likely currently-valid creds, prioritize.", file=sys.stderr)


if __name__ == "__main__":
    main()
