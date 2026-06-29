# Sandbox Escape — AppContainer / LPAC & Browser Renderer

AppContainer is Windows' deny-by-default process sandbox (Untrusted integrity + capability
SIDs); **LPAC** (Less Privileged AppContainer) is the stricter variant where even
registry/file/COM access requires explicit capabilities. Browser renderers (Chromium/Edge),
packaged apps, and many parsers run here. Escaping means crossing from the container to a
broker (normal user / Medium) or straight to the kernel.

## Theory / Mechanism

An AppContainer token carries an **AppContainer SID** + a set of **capability SIDs**;
the kernel denies access to objects whose DACL does not grant the package/capability SID.
Specific restrictions: no arbitrary file/registry/network/credential access; **localhost
is blocked** (to stop trivial pivots into local services); inter-process work must go
through a **broker**. LPAC additionally denies registry (`registryRead` cap needed), COM
(`lpacCom` cap needed), etc.

Escape vectors, in order of reliability:

1. **Kernel bug (always available)** — AppContainer is *userland* enforcement. Any kernel
   R/W (see `kernel-user-boundary.md` / `byovd-kernel-rw.md`) bypasses the entire sandbox.
   `win32k` syscall filtering shrinks but does not eliminate the surface, and `dxgkrnl`
   (DirectX, used by the GPU process) remains reachable. CVE-2025-24983 / CVE-2025-62573
   are the kind of bugs that finish a renderer chain.
2. **Broker abuse** — the broker mediates privileged actions for the container. If a
   broker exposes an object cross-process with weak validation, the container drives it.
   The canonical pattern is **partial-trust WinRT classes** instantiated inside a
   **RuntimeBroker** at normal-user privilege: the *XmlDocument insecure-sharing* class of
   bug let an Edge Content LPAC process obtain an `XmlDocument` living in the broker and
   leverage its file-access methods to escape.
3. **IPC logic bug (browser)** — see Chromium/Mojo below.
4. **Named-object / symbolic-link squatting** — historically dominant (used against Chrome,
   IE, Adobe Reader sandboxes). Mostly mitigated since 2017 by `RtlIsSandboxToken`:
   `ObpParseSymbolicLink` refuses to resolve a link **created by a sandboxed token when the
   follower is not sandboxed**, killing sandbox→unsandboxed link elevation. Object-manager
   **mount-point/symlink squatting** can still work sandbox→sandbox, and weak-DACL named
   objects (sections, pipes) that a higher-privilege process opens remain abusable.
5. **Capability over-grant** — an app shipped with `internetClient`,
   `privateNetworkClientServer`, `documentsLibrary` etc. widens reachable surface (e.g.
   localhost becomes reachable → attack a local service).

`sandbox_escape_probe.py`, run *inside* the sandboxed process, enumerates integrity,
AppContainer membership, visible named pipes, and whether localhost is blocked, then ranks
these vectors for the current context.

## Browser Renderer → Browser Process (Chromium / Edge, Mojo IPC)

Chromium runs the renderer in an AppContainer; the privileged Browser process is reached
only through **Mojo** IPC. A modern Chrome chain in 2025 needs ~3 bugs: a V8 type confusion
(renderer corruption) → a V8 heap-sandbox escape → an **OS-level sandbox escape via a Mojo
logic bug**.

Verified 2025 Mojo escapes:

| CVE | Layer | Mechanism | Notes |
|-----|-------|-----------|-------|
| **CVE-2025-2783** | Mojo (Windows) | Incorrect/privileged **handle delivered to the wrong process** under a logic error at the Chrome-sandbox / Windows boundary | Exploited ITW as *Operation ForumTroll* (Kaspersky), patched Chrome 134.0.6998.177 / Edge 134.0.3124.93; CISA KEV. The renderer receives a handle it should not, breaking broker confinement. |
| **CVE-2025-4609** | ipcz transport | `Transport::Deserialize` didn't validate `header.destination_type`, letting a compromised renderer **forge a transport to impersonate the broker** and obtain privileged handles | Patched 136.0.7103.113/.114; supply-chain tail — downstream Electron-style apps (Cursor, Windsurf) lagged the fix. |
| **CVE-2025-2857** | Firefox IPC | Same class — child leaks a privileged handle from parent | Mozilla found it by auditing after CVE-2025-2783. Useful cross-reference for the pattern. |

Detection-relevant: EDRs rarely inspect **Mojo IPC traffic**, which is exactly where the
breakout happens — watch for the renderer/GPU process spawning non-standard children or
unexpected handle transfers instead.

## Modern 2024-2026 Variants (verified)

- **CVE-2025-2783** (Chrome Mojo handle confusion, ITW) and **CVE-2025-4609** (ipcz
  Transport::Deserialize) — the two headline Windows Chromium sandbox escapes; both affect
  all Chromium-based browsers including Edge/Brave until rebuilt.
- Kernel bugs usable to finish a sandbox-aware chain: **CVE-2025-24983** (`win32k` UAF,
  ITW), **CVE-2025-62573** (`dxgkrnl` UAF, reachable via GPU process).
- Symbolic-link mitigation (`RtlIsSandboxToken` / `ObpParseSymbolicLink`) remains the
  reason classic squatting is now mostly sandbox→sandbox only.

## Complete Workflow

```cmd
:: From inside the renderer/packaged app: map escape surface and rank vectors
python sandbox_escape_probe.py
python sandbox_escape_probe.py --json > surface.json

:: Confirm patch state of installed Chromium browsers (escape relevance)
reg query "HKLM\SOFTWARE\Microsoft\Edge\BLBeacon" /v version
:: Edge < 134.0.3124.93  -> CVE-2025-2783 reachable
:: Chrome < 134.0.6998.178 -> CVE-2025-2783 reachable
```

Conceptual full chain (authorized research):

```
V8 type confusion (renderer RCE, Untrusted)
   -> V8 heap-sandbox bypass (escape the cage)
   -> Mojo handle confusion (CVE-2025-2783) => privileged handle in renderer
   -> drive broker handle to read/write outside sandbox  (Browser process, Medium)
   -> kernel bug (CVE-2025-24983 / dxgkrnl) or UAC bypass => SYSTEM
```

## Detection

```yaml
title: Browser Sandbox Escape Indicators
id: 7c2b44a9-5d11-4e80-b6f3-sbxesc001
logsource: { product: windows, category: process_creation }
detection:
  renderer_spawn:
    ParentImage|endswith:
      - '\msedge.exe'
      - '\chrome.exe'
    ParentCommandLine|contains:
      - '--type=renderer'
      - '--type=gpu-process'
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\rundll32.exe'
      - '\regsvr32.exe'
  condition: renderer_spawn
level: high
```

- **Process genealogy**: a sandboxed renderer/GPU child should never spawn `cmd`,
  `powershell`, `rundll32`. Any such child = post-escape execution.
- **Handle-transfer anomalies** between renderer and broker (Mojo escape primitive) — needs
  ETW handle auditing; rarely instrumented, so process-spawn is the practical signal.
- **Patch posture**: alert on Edge/Chrome below the CVE-2025-2783 fix version on managed
  hosts.
- **RuntimeBroker** performing file/object operations on behalf of an AppContainer that the
  package shouldn't need (broker-abuse IOC).

## OPSEC

- **What it touches**: a pure IPC/kernel escape is memory-only inside the browser process
  tree; the loud moment is the first *out-of-sandbox* action (child process, file write).
- **Cleanup**: nothing persistent in a clean chain; avoid spawning child processes — do the
  next stage in-process (reflective load) to stay within the browser's expected behavior.
- **Evasion**: keep execution inside the browser process model as long as possible; the
  IPC layer is an EDR blind spot. Symbolic-link squatting is largely dead post-2017 — don't
  rely on it against modern targets except sandbox→sandbox.
- **Hard stops**: patched browsers (CVE-2025-2783/4609), `win32k` lockdown for the
  renderer, HVCI/KDP for the kernel finisher, and per-app capability minimization (no
  `internetClient` → no localhost pivot).

## References

- Kaspersky / Securelist — *Operation ForumTroll*, CVE-2025-2783 root cause (Mojo handle).
- Chromium issue tracker + SentinelOne/Fidelis/Sangfor write-ups — CVE-2025-2783.
- OX Security — CVE-2025-4609 (ipcz `Transport::Deserialize`) + downstream supply-chain tail.
- Penligent — "Chrome 2025 Zero-Days: the ANGLE/V8/Mojo kill chain" (3-bug model).
- Google Project Zero — "Understanding Network Access in Windows AppContainers" (localhost
  block) and the 2015 symbolic-link/`RtlIsSandboxToken` mitigation analysis.
- HackMag — "Isolating Windows Processes with LPAC"; James Forshaw — XmlDocument insecure
  sharing / COM Desktop Broker LPAC escapes.
