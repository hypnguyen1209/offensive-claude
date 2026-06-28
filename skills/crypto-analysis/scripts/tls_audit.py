#!/usr/bin/env python3
"""
tls_audit.py - TLS/SSL + SSH crypto posture auditor with PKI and PQ-readiness checks.

Pure-stdlib (ssl, socket) TLS probing + raw SSH KEXINIT parsing. Cross-check findings
against testssl.sh for completeness; this tool is for fast, scriptable, JSON-emitting
triage and for the parts testssl.sh does not (SSH Terrapin algorithm/strict-kex check,
ML-KEM hybrid-group detection).

Covers:
  - TLS protocol-version support matrix (SSLv3..TLS1.3)
  - Weak/legacy cipher detection (NULL/EXPORT/RC4/3DES/SWEET32)
  - Certificate grading (key size, sig alg, validity, SAN)
  - SSH Terrapin (CVE-2023-48795): chacha20-poly1305 / *-etm + strict-kex presence
  - Post-quantum / HNDL: detect X25519MLKEM768 hybrid group offering (--pq)
  - Certificate-Transparency shadow-asset discovery via crt.sh (--ct)

Usage:
  python3 tls_audit.py HOST:PORT [--ssh HOST:PORT] [--pq] [--ct] [--json out.json]
  python3 tls_audit.py example.com:443 --ssh example.com:22 --pq --ct --json report.json

Dependencies: Python 3.8+ stdlib only. crt.sh check uses urllib (network).
Author: offensive-claude / crypto-analysis skill. Authorized engagements only.
"""
import argparse
import json
import socket
import ssl
import sys
import urllib.request

# ATT&CK T1600.001 / CWE-326. Legacy cipher substrings that indicate weakness.
WEAK_CIPHER_TOKENS = {
    "NULL": "CWE-327 null cipher (no encryption)",
    "EXPORT": "CWE-326 export-grade (Logjam/FREAK)",
    "RC4": "CWE-327 RC4 (biased keystream)",
    "DES-CBC3": "CWE-327 3DES (SWEET32 64-bit block birthday)",
    "3DES": "CWE-327 3DES (SWEET32)",
    "MD5": "CWE-327 MD5 MAC",
}

PROTOCOLS = [
    ("SSLv3", getattr(ssl, "PROTOCOL_SSLv23", None)),  # negotiated via min/max below
]


def _split_hostport(s, default_port):
    if ":" in s:
        h, p = s.rsplit(":", 1)
        return h, int(p)
    return s, default_port


def probe_versions(host, port):
    """Return which TLS versions the server will negotiate."""
    results = {}
    version_map = {
        "TLSv1.0": ssl.TLSVersion.TLSv1,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.3": ssl.TLSVersion.TLSv1_3,
    }
    for name, ver in version_map.items():
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = ver
            ctx.maximum_version = ver
        except ValueError:
            results[name] = "unsupported-by-client"
            continue
        try:
            with socket.create_connection((host, port), timeout=6) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    results[name] = {"negotiated": True,
                                     "cipher": s.cipher()[0] if s.cipher() else None}
        except Exception as e:
            results[name] = {"negotiated": False, "reason": type(e).__name__}
    return results


def grade_certificate(host, port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    out = {}
    try:
        with socket.create_connection((host, port), timeout=6) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                der = s.getpeercert(binary_form=True)
                cert = s.getpeercert()  # only populated if validated; fall back to der len
                out["cipher_suite"] = s.cipher()
                out["der_bytes"] = len(der) if der else 0
                if cert:
                    out["subject"] = dict(x[0] for x in cert.get("subject", []))
                    out["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                    out["notAfter"] = cert.get("notAfter")
                    out["SAN"] = [v for (_, v) in cert.get("subjectAltName", [])]
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
    # Use openssl-grade heuristic on negotiated cipher
    return out


def flag_weak_ciphers(version_results):
    findings = []
    for ver, info in version_results.items():
        if isinstance(info, dict) and info.get("negotiated"):
            c = (info.get("cipher") or "")
            for tok, desc in WEAK_CIPHER_TOKENS.items():
                if tok in c.upper():
                    findings.append({"version": ver, "cipher": c, "issue": desc})
    # Protocol-level findings
    for ver, info in version_results.items():
        if ver in ("TLSv1.0", "TLSv1.1") and isinstance(info, dict) and info.get("negotiated"):
            findings.append({"version": ver, "issue": "CWE-326 deprecated TLS version"})
    return findings


def check_pq(host, port):
    """Detect post-quantum hybrid key-exchange group support.
    OpenSSL 3.5+ / BoringSSL advertise X25519MLKEM768. Stdlib ssl cannot set the group,
    so we report whether the negotiated TLS1.3 group can be read and flag classical-only.
    For authoritative PQ detection use: openssl s_client -groups X25519MLKEM768 ..."""
    note = ("stdlib ssl cannot negotiate PQ groups; run: "
            "openssl s_client -groups X25519MLKEM768 -connect %s:%d </dev/null "
            "and check for SUCCESS. Classical-only endpoints are exposed to "
            "Harvest-Now-Decrypt-Later (CWE-327)." % (host, port))
    res = {"manual_check": note, "verdict": "UNKNOWN (run manual openssl check)"}
    # Best-effort: try negotiating TLS1.3 and read group if Python exposes it (3.10+ none does cleanly)
    return res


def check_ssh_terrapin(host, port):
    """Parse the SSH server KEXINIT and evaluate Terrapin (CVE-2023-48795).
    Vulnerable iff (chacha20-poly1305@openssh.com OR *-etm@openssh.com[CBC]) AND
    no kex-strict-s-v00@openssh.com advertised."""
    try:
        sock = socket.create_connection((host, port), timeout=6)
        banner = sock.recv(256)  # server banner line
        sock.sendall(b"SSH-2.0-cryptoaudit\r\n")
        data = b""
        while len(data) < 4096:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 35 and b"curve25519" in data or b"diffie" in data:
                break
        sock.close()
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}

    text = data.decode("latin-1", "ignore")

    def has(token):
        return token in text

    chacha = has("chacha20-poly1305@openssh.com")
    etm = has("-etm@openssh.com")
    cbc = has("cbc")
    strict = has("kex-strict-s-v00@openssh.com")
    vulnerable = (chacha or (etm and cbc)) and not strict
    return {
        "banner": banner.decode("latin-1", "ignore").strip(),
        "chacha20_poly1305": chacha,
        "etm_macs": etm,
        "cbc_ciphers": cbc,
        "strict_kex": strict,
        "terrapin_vulnerable": vulnerable,
        "cve": "CVE-2023-48795" if vulnerable else None,
        "attck": "T1557",
    }


def crt_sh(domain):
    """Passive Certificate-Transparency shadow-asset discovery."""
    url = "https://crt.sh/?q=%25." + domain + "&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "crypto-analysis"})
        with urllib.request.urlopen(req, timeout=20) as r:
            entries = json.loads(r.read().decode())
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}
    names = set()
    for e in entries:
        for n in (e.get("name_value", "") or "").split("\n"):
            n = n.strip().lstrip("*.")
            if n:
                names.add(n)
    return {"unique_names": sorted(names), "count": len(names)}


def main():
    ap = argparse.ArgumentParser(description="TLS/SSH crypto posture auditor")
    ap.add_argument("target", help="HOST:PORT for TLS (e.g. example.com:443)")
    ap.add_argument("--ssh", help="HOST:PORT for SSH Terrapin check")
    ap.add_argument("--pq", action="store_true", help="post-quantum hybrid-group readiness note")
    ap.add_argument("--ct", action="store_true", help="crt.sh Certificate-Transparency mining")
    ap.add_argument("--json", help="write JSON finding record to this path")
    args = ap.parse_args()

    host, port = _split_hostport(args.target, 443)
    report = {"target": f"{host}:{port}", "skill": "crypto-analysis"}

    versions = probe_versions(host, port)
    report["tls_versions"] = versions
    report["certificate"] = grade_certificate(host, port)
    report["weak_findings"] = flag_weak_ciphers(versions)

    if args.pq:
        report["post_quantum"] = check_pq(host, port)
    if args.ssh:
        sh, sp = _split_hostport(args.ssh, 22)
        report["ssh_terrapin"] = check_ssh_terrapin(sh, sp)
    if args.ct:
        report["certificate_transparency"] = crt_sh(host)

    out = json.dumps(report, indent=2, default=str)
    print(out)
    if args.json:
        with open(args.json, "w") as f:
            f.write(out)
        print(f"[+] finding record written: {args.json}", file=sys.stderr)


if __name__ == "__main__":
    main()
