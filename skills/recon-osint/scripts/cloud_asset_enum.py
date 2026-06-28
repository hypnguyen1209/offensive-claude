#!/usr/bin/env python3
"""
cloud_asset_enum.py — Combined cloud + SaaS + source-code recon.

Three independent modules (run any subset):
  1. STORAGE  : permute a keyword and probe AWS S3 / Azure Blob / GCS namespaces (DNS+HTTP).
  2. AZURE    : unauthenticated Entra/Azure tenant recon via getuserrealm + OpenID config.
                Post the June-2025 Get-AADIntTenantDomains patch, per-domain realm probing is the
                supported path (full multi-domain enumeration via Exchange is dead).
  3. GITHUB   : org-wide secret scanning by shelling out to trufflehog (verified-only).

USAGE:
  python3 cloud_asset_enum.py -k target --company targetcorp \
      --azure-domain target.com --gh-org targetcorp --gh-token "$GH_TOKEN" -o cloud_out/

  # storage only:   python3 cloud_asset_enum.py -k target --company targetcorp -o out/
  # azure only:      python3 cloud_asset_enum.py --azure-domain target.com -o out/

DEPENDENCIES:  pip install requests dnspython ; (optional) trufflehog on $PATH for --gh-org

OPSEC: storage/github probes hit the PROVIDER (logged in their account, not the target's). Azure
realm/OpenID probes are unauthenticated and invisible to the tenant's sign-in logs. Verify any found
bucket/blob actually belongs to your target before reporting.

Authorized engagements only.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:
    print("[!] pip install requests dnspython", file=sys.stderr)
    raise

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0 Safari/537.36"
SESS = requests.Session()
SESS.headers.update({"User-Agent": UA})

# Permutation affixes for storage-name fuzzing.
AFFIX = ["", "-dev", "-staging", "-stage", "-prod", "-production", "-test", "-qa", "-uat",
         "-backup", "-backups", "-bak", "-logs", "-log", "-data", "-assets", "-static",
         "-media", "-files", "-public", "-private", "-internal", "-archive", "-cdn",
         "-images", "-img", "-uploads", "-storage", "-db", "-dump", "-temp"]


def perms(keyword, company):
    bases = {keyword, company, company.replace("-", ""), company.replace(" ", "")}
    names = set()
    for b in filter(None, bases):
        for a in AFFIX:
            names.add(f"{b}{a}")
            names.add(f"{a.lstrip('-')}{b}" if a else b)
            names.add(f"{b}{a.replace('-', '')}" if a else b)
    return sorted(n for n in names if n)


def probe_s3(name):
    """Return (state, url) where state in open/protected/none."""
    for url in (f"https://{name}.s3.amazonaws.com", f"https://s3.amazonaws.com/{name}"):
        try:
            r = SESS.get(url, timeout=8)
        except requests.RequestException:
            continue
        if r.status_code == 200 and "<ListBucketResult" in r.text:
            return "open", url
        if r.status_code == 403 or "AccessDenied" in r.text:
            return "protected", url
        if r.status_code == 404 and "NoSuchBucket" in r.text:
            return "none", url
    return "none", ""


def probe_azure_blob(name):
    url = f"https://{name}.blob.core.windows.net/?comp=list"
    try:
        r = SESS.get(url, timeout=8)
    except requests.RequestException:
        return "none", ""
    if r.status_code in (200, 400, 409) and "blob.core.windows.net" in r.url:
        # account exists (resolves); 200 with container list = open
        if "<EnumerationResults" in r.text:
            return "open", url
        return "exists", f"https://{name}.blob.core.windows.net/"
    return "none", ""


def probe_gcs(name):
    url = f"https://storage.googleapis.com/{name}"
    try:
        r = SESS.get(url, timeout=8)
    except requests.RequestException:
        return "none", ""
    if r.status_code == 200 and "<ListBucketResult" in r.text:
        return "open", url
    if r.status_code == 403 or "AccessDenied" in r.text:
        return "protected", url
    return "none", ""


def storage_module(keyword, company, threads, out):
    cands = perms(keyword, company)
    print(f"[*] storage: {len(cands)} candidate names x 3 clouds", file=sys.stderr)
    hits = []
    tasks = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        for n in cands:
            tasks.append((ex.submit(probe_s3, n), "aws-s3", n))
            tasks.append((ex.submit(probe_azure_blob, n), "azure-blob", n))
            tasks.append((ex.submit(probe_gcs, n), "gcs", n))
        for fut, cloud, n in tasks:
            try:
                state, url = fut.result()
            except Exception:  # noqa: BLE001
                continue
            if state not in ("none", ""):
                rec = {"cloud": cloud, "name": n, "state": state, "url": url}
                hits.append(rec)
                print(f"[STORAGE] {cloud:12} {state:9} {n}  {url}", file=sys.stderr)
    with open(os.path.join(out, "storage.jsonl"), "w", encoding="utf-8") as f:
        for h in hits:
            f.write(json.dumps(h) + "\n")
    print(f"[+] storage hits: {len(hits)}", file=sys.stderr)


def azure_module(domain, out):
    print(f"[*] azure tenant recon: {domain}", file=sys.stderr)
    rec = {"domain": domain}
    # 1. getuserrealm — managed vs federated, namespace type, brand, federation host
    try:
        r = SESS.get("https://login.microsoftonline.com/getuserrealm.srf",
                     params={"login": f"user@{domain}", "json": "1"}, timeout=10)
        rec["userrealm"] = r.json()
    except Exception as e:  # noqa: BLE001
        rec["userrealm_error"] = str(e)
    # 2. OpenID config — tenant GUID, region, endpoints
    try:
        r = SESS.get(f"https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration",
                     timeout=10)
        if r.status_code == 200:
            cfg = r.json()
            rec["tenant_present"] = True
            rec["issuer"] = cfg.get("issuer")
            rec["token_endpoint"] = cfg.get("token_endpoint")
            rec["tenant_region_scope"] = cfg.get("tenant_region_scope")
            # tenant GUID lives in the issuer URL
            import re
            m = re.search(r"[0-9a-fA-F-]{36}", cfg.get("issuer", ""))
            rec["tenant_id"] = m.group(0) if m else None
        else:
            rec["tenant_present"] = False
    except Exception as e:  # noqa: BLE001
        rec["openid_error"] = str(e)
    with open(os.path.join(out, "azure_tenant.json"), "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=2)
    print(f"[+] azure: tenant_present={rec.get('tenant_present')} "
          f"tenant_id={rec.get('tenant_id')} "
          f"realm={rec.get('userrealm', {}).get('NameSpaceType')}", file=sys.stderr)


def github_module(org, token, out):
    if not shutil.which("trufflehog"):
        print("[!] trufflehog not on PATH — skipping github module. "
              "Install: https://github.com/trufflesecurity/trufflehog", file=sys.stderr)
        return
    print(f"[*] github org secret scan: {org}", file=sys.stderr)
    cmd = ["trufflehog", "github", f"--org={org}", "--results=verified",
           "--include-wikis", "--issue-comments", "--pr-comments", "--gist-comments", "--json"]
    env = os.environ.copy()
    if token:
        cmd.append(f"--token={token}")
    outfile = os.path.join(out, "github_secrets.jsonl")
    with open(outfile, "w", encoding="utf-8") as f:
        subprocess.run(cmd, stdout=f, stderr=subprocess.DEVNULL, env=env)
    n = sum(1 for _ in open(outfile, encoding="utf-8", errors="replace"))
    print(f"[+] github verified secrets: {n} -> {outfile}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description="Cloud + SaaS + source-code recon")
    ap.add_argument("-k", "--keyword", help="primary keyword for storage perms")
    ap.add_argument("--company", default="", help="company/brand name for storage perms")
    ap.add_argument("--azure-domain", help="domain for Azure tenant recon")
    ap.add_argument("--gh-org", help="GitHub org for trufflehog scan")
    ap.add_argument("--gh-token", help="GitHub PAT (recommended; raises rate limit)")
    ap.add_argument("--threads", type=int, default=30)
    ap.add_argument("-o", "--out", default="cloud_out")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    if args.keyword:
        storage_module(args.keyword, args.company or args.keyword, args.threads, args.out)
    if args.azure_domain:
        azure_module(args.azure_domain, args.out)
    if args.gh_org:
        github_module(args.gh_org, args.gh_token, args.out)
    if not (args.keyword or args.azure_domain or args.gh_org):
        ap.error("supply at least one of -k / --azure-domain / --gh-org")
    print(f"[+] DONE. artifacts in {args.out}/", file=sys.stderr)


if __name__ == "__main__":
    main()
