# RPC / ALPC & Named-Pipe Impersonation Boundary

RPC (over ALPC locally) and named pipes are the trust boundary between low-privilege
service accounts and SYSTEM. The whole "Potato" family, and the 2026 **PhantomRPC**
architecture flaw, exploit one idea: coerce a privileged client to authenticate to an
attacker-controlled endpoint, then **impersonate** it to become SYSTEM. This is the standard
finisher for any foothold holding `SeImpersonatePrivilege` (default on `NETWORK SERVICE` /
`LOCAL SERVICE`, IIS/MSSQL app-pool identities, etc.).

## Theory / Mechanism

**Named-pipe client impersonation** (the reusable primitive): a server creates a pipe with
a NULL/weak DACL, a privileged client connects, the server calls
`ImpersonateNamedPipeClient` to adopt the client's token, `DuplicateTokenEx` to a primary
token, and `CreateProcessWithTokenW`/`CreateProcessAsUser` to spawn SYSTEM. The only
requirement is `SeImpersonatePrivilege`. `named_pipe_impersonate.c` implements the full
server side; you supply the coercion of a SYSTEM client.

**ALPC layer**: an ALPC port is a message channel; the connect call carries
`ALPC_PORT_ATTRIBUTES` → `SECURITY_QUALITY_OF_SERVICE` defining the **impersonation level**
the server may use, and `RequiredServerSid` naming the expected server identity. RPC sits on
top: when a client calls a server, the server can `RpcImpersonateClient` to run as the
caller — the privilege boundary hinges entirely on the client choosing
`SecurityImpersonation`/`SecurityDelegation` SQoS.

**Coercion methods** (how to get a SYSTEM client to connect):
- DCOM/BITS OXID-resolver coercion (classic *RottenPotato*/*JuicyPotato*).
- `SpoolSS` over `\pipe\spoolss` (*PrintSpoofer*).
- `RpcSs`/`DComLaunch` activation (*RoguePotato*, *JuicyPotatoNG*, *GodPotato*, *SigmaPotato*).
- Endpoint squatting (**PhantomRPC**, below) — no coercion service needed.

## PhantomRPC (2026, Kaspersky / Black Hat Asia 2026 — Haidar Kabibo)

An **architectural** RPC flaw: an RPC **client connecting to a server does not verify the
server's identity strongly enough**, so *any process can stand up an RPC server that mimics
a legitimate service and receive the calls intended for the real one*. If those calls come
from a privileged client connecting with a high impersonation level, the attacker's server
calls **`RpcImpersonateClient`** and escalates — low-priv service account → SYSTEM.

Five disclosed paths; notable ones:
- **`gpupdate.exe` / Group Policy Client**: `gpupdate /force` makes the SYSTEM GPClient
  service RPC-call `TermService`. **If TermService is disabled**, the attacker's fake RPC
  server intercepts → SYSTEM.
- **`msedge.exe` startup** issues a high-impersonation RPC call to `TermService`.
- **`w32tm.exe` / Windows Time** first tries a *nonexistent* named pipe `\PIPE\W32TIME`;
  squat that endpoint (no need to disable W32Time) and impersonate any privileged user who
  runs the binary.

**Status**: reported to MSRC 2025-09-19; Microsoft rated it *moderate* (requires
`SeImpersonatePrivilege`, already held by service accounts), **no CVE, no scheduled fix** —
treat as a live, unpatched LPE primitive. `named_pipe_impersonate.c` covers the
endpoint-squat + impersonate half (e.g. squat `\\.\pipe\W32TIME`).

## Modern 2024-2026 Variants (verified)

- **PhantomRPC** (Kaspersky/Securelist, Black Hat Asia 2026) — five RPC server-spoofing /
  endpoint-squat paths to SYSTEM; unpatched, no CVE.
- **WER ALPC LPE** — public PoC for a Windows Error Reporting ALPC privilege escalation
  (cybersecuritynews, 2025/2026) — ALPC endpoint as the LPE surface.
- Potato lineage still current on supported builds where `SeImpersonate` is present:
  **GodPotato** / **SigmaPotato** (DCOM activation, work on Win10/11/Server up to 2022+),
  **JuicyPotatoNG**, **PrintSpoofer** (spoolss). RPC-server-binding hardening killed older
  RoguePotato variants on some builds, but DCOM-activation potatoes persist.

## Complete Workflow

```cmd
:: 1. Confirm we hold SeImpersonatePrivilege (the gate for everything here)
whoami /priv | findstr SeImpersonate

:: 2a. PhantomRPC endpoint-squat: occupy a pipe a SYSTEM binary will connect to,
::     then trigger that binary (e.g. w32tm /resync), and impersonate the caller.
named_pipe_impersonate.exe \\.\pipe\W32TIME "C:\Windows\System32\cmd.exe"
::     (in another context / once the SYSTEM client connects -> SYSTEM shell)
w32tm /resync

:: 2b. PhantomRPC gpupdate path (requires TermService disabled):
sc query TermService                 :: confirm STOPPED/DISABLED
named_pipe_impersonate.exe \\.\pipe\<termservice-endpoint> "cmd.exe /c whoami>C:\p.txt"
gpupdate /force

:: 3. Classic alternative if a coercion service is available:
PrintSpoofer.exe -i -c cmd           :: spoolss coercion
GodPotato.exe -cmd "cmd /c whoami"   :: DCOM activation
```

Enumerate the local RPC/ALPC + pipe surface (which endpoints exist / are squattable):

```powershell
# NtObjectManager (James Forshaw) - list RPC endpoints + ALPC ports
Import-Module NtObjectManager
Get-RpcEndpoint | Select InterfaceId, Annotation, BindingString
Get-NtDirectory \RPC Control | Get-NtDirectoryEntry        # ALPC ports
[System.IO.Directory]::GetFiles('\\.\pipe\')               # existing pipes
```

## Detection

```yaml
title: Token Impersonation to SYSTEM via Named Pipe / RPC (Potato/PhantomRPC)
id: c90e21b4-7af3-4d52-8e66-rpcalpc001
logsource: { product: windows }
detection:
  pipe_impersonation:                  # Elastic "Named Pipe Impersonation"
    EventID: 4624
    LogonType: 9                       # NewCredentials / impersonation logon
    LogonProcessName: 'Advapi'
  spawn_as_system:                     # 4688 child as SYSTEM from a service acct parent
    EventID: 4688
    SubjectUserSid|startswith: 'S-1-5-'   # service account
    TargetUserSid: 'S-1-5-18'             # SYSTEM
  rpc_unavailable:                     # PhantomRPC ETW signal
    Provider: 'Microsoft-Windows-RPC'
    EventID: 1
    Status: 'RPC_S_SERVER_UNAVAILABLE'
  condition: pipe_impersonation or spawn_as_system or rpc_unavailable
level: high
```

- **`ImpersonateNamedPipeClient` → `CreateProcessWithTokenW`** chain: Logon type **9**
  (NewCredentials) from `Advapi`, plus a SYSTEM child of a service-account parent
  (Elastic prebuilt rule "Privilege Escalation via Named Pipe Impersonation").
- **PhantomRPC**: enable ETW **RPC client/server** tracing and alert on
  `RPC_S_SERVER_UNAVAILABLE` (Event ID 1) combined with **high impersonation levels** from
  privileged processes — Kaspersky's recommended interim detection.
- **Pipe creation with NULL DACL** for names mimicking system endpoints (`spoolss`,
  `W32TIME`, RPC control names) by a non-system process (Sysmon EID 17/18).
- **`RpcFilter`/RPC firewall** logs of unexpected interface binds.

## OPSEC

- **What it touches**: a named pipe / ALPC port (transient, in-memory) and a spawned SYSTEM
  process — the spawned child is the visible artifact. No disk footprint for the primitive
  itself.
- **Cleanup**: `RevertToSelf`, close the pipe handle, and avoid spawning an obvious
  `cmd.exe` — duplicate the token and perform the objective in-process where possible.
- **Evasion**: PhantomRPC endpoint-squat avoids the loud DCOM-activation pattern that EDR
  rules key on for potatoes; choosing a benign-looking endpoint (`W32TIME`) and triggering
  it via a legitimate admin action (`w32tm /resync`, `gpupdate /force`) blends with normal
  activity. Prefer `CreateProcessWithTokenW` (needs `SeImpersonate`) over
  `CreateProcessAsUser` (needs `SeAssignPrimaryToken`) based on which privilege you hold.
- **Hard stops**: removing `SeImpersonatePrivilege` from the service identity defeats the
  whole family; EPA/strong SQoS handling and not-disabling depended-upon services close
  specific PhantomRPC paths. Microsoft considers this "by design" given the privilege
  requirement, so detection (not patching) is the realistic control.

## References

- Kaspersky / Securelist — "PhantomRPC: a new privilege-escalation technique in Windows RPC"
  (Black Hat Asia 2026, Haidar Kabibo); Dark Reading coverage of the unpatched flaw.
- cybersecuritynews — "PoC for Windows Error Reporting ALPC Privilege Escalation".
- HackTricks — "Named Pipe Client Impersonation"; Elastic prebuilt rule
  "Privilege Escalation via Named Pipe Impersonation".
- Potato family: PrintSpoofer (itm4n), GodPotato, SigmaPotato, JuicyPotatoNG.
- James Forshaw — NtObjectManager RPC/ALPC enumeration.
