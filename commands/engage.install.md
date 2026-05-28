---
description: Execute Phase 5 - Installation and Persistence Establishment
---

# /engage.install

Executes Phase 5 (Installation/Persistence) of the engagement workflow.

## Usage

`/engage.install [--method <persistence-method>]`

Options:
- `--method`: Specify persistence method (service, cron, startup, registry, implant)

## Process

### 1. Load Templates
Loads:
- `install/persistence-mechanism.md` — Persistence design and implementation
- `install/cleanup-plan.md` — Cleanup and removal procedures

### 2. Environment Assessment
Before installing persistence:
- Identify current access level and user context
- Enumerate installed security controls (AV, EDR, HIDS)
- Identify available persistence locations
- Assess detection risk for each method

### 3. Persistence Method Selection
Choose method based on target environment and OPSEC requirements:

**Linux Methods**:
- Cron job (user or system level)
- Systemd service or timer
- Bashrc/profile modification
- SSH authorized_keys
- Kernel module (requires root)
- LD_PRELOAD hijacking

**Windows Methods**:
- Registry run keys
- Scheduled task
- Windows service
- WMI event subscription
- DLL hijacking/side-loading
- COM object hijacking
- Startup folder

**Cross-Platform Methods**:
- Web shell
- Implant with auto-reconnect
- Backdoored application binary

### 4. Implementation
Documents in `persistence-mechanism.md`:

**Persistence Details**:
- Method selected and justification
- Installation location (path, registry key, etc.)
- Execution trigger (boot, login, scheduled, event-based)
- Payload stored/dropped
- Expected behavior after installation

**Stealth Considerations**:
- File timestamps (timestomp if needed)
- Log suppression or cleanup
- AV/EDR evasion for persistence mechanism
- Naming conventions (blend with legitimate entries)
- Digital signatures (if applicable)

### 5. Verification
After installation:
- Verify persistence survives reboot/relogin
- Confirm callback to C2
- Test failover and recovery
- Monitor for security alerts

### 6. Cleanup Plan
Populates `cleanup-plan.md` with:

**Cleanup Steps** (ordered):
- Exact commands to remove persistence
- Files to delete
- Registry keys to remove
- Services to stop and delete
- Logs to review for artifacts

**Cleanup Verification**:
- How to verify complete removal
- Host artifacts that may remain
- Network indicators to deconflict

### 7. Gate Check
Validates:
- Persistence method documented
- Installation verified functional
- Cleanup plan created with specific removal steps
- OPSEC considerations addressed

### 8. Next Steps
If gate passes, suggests: `/engage.c2`

## Example Output

```
Starting Phase 5: Installation

Current access:
  User: root (via privesc from Phase 4)
  Host: admin.acme-corp.com (10.0.1.42)
  OS: Ubuntu 20.04 LTS

Security controls detected:
  AV: ClamAV (signature-based)
  EDR: None
  HIDS: OSSEC

Available persistence methods:
1. Cron job — Low detection risk
2. Systemd service — Medium detection risk
3. SSH authorized_keys — Low detection risk
4. Bashrc modification — Low detection risk

Recommended: Systemd service (survives reboot, auto-restart)
Alternate: Cron job (simpler, lower footprint)

Which method?
> 1 (Systemd service)

Installing persistence...

→ Creating service unit file...
  /etc/systemd/system/syslog-ng-helper.service
  (named to blend with legitimate services)

→ Configuring service...
  ExecStart: /usr/lib/syslog-ng/.helper
  Restart: always
  RestartSec: 30s

→ Enabling service...
  systemctl daemon-reload
  systemctl enable syslog-ng-helper.service
  systemctl start syslog-ng-helper.service

→ Verifying persistence...
  Service status: active (running)
  Callback: Received at C2

→ Testing reboot survival...
  (Manual verification recommended)

Cleanup Plan Created:
  1. systemctl stop syslog-ng-helper.service
  2. systemctl disable syslog-ng-helper.service
  3. rm /etc/systemd/system/syslog-ng-helper.service
  4. rm /usr/lib/syslog-ng/.helper
  5. systemctl daemon-reload
  6. Verify removal: systemctl list-units | grep helper

OPSEC Notes:
  - File timestamp set to match other files in /usr/lib/syslog-ng/
  - Service name mimics legitimate syslog service
  - Binary has no suspicious strings

Running gate validation...

✓ Phase 5 (Installation) gate validation PASSED
Ready to proceed to Phase 6 (C2).
Run: /engage.c2
```

## Available Skills

- `17-edr-evasion` — EDR/AV bypass for persistence
- `14-red-team-ops` — Red team persistence techniques
- `24-advanced-redteam` — Advanced OPSEC and staged payloads

## Notes

Always create a detailed cleanup plan before installing persistence. Every artifact must be removable at engagement conclusion.
