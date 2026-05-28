---
description: Execute Phase 3 - Delivery and Payload Deployment
---

# /engage.deliver

Executes Phase 3 (Delivery) of the engagement workflow.

## Usage

`/engage.deliver [--vector <delivery-method>]`

Options:
- `--vector`: Specify delivery method (web, email, physical, remote)

## Process

### 1. Load Template
Loads `delivery/delivery-plan.md` template.

### 2. Delivery Vector Selection
Reviews weaponization output and prompts:
- What delivery method is authorized per ROE?
- What is the target's attack surface?
- What delivery method has highest success probability?

**Delivery Vectors**:
- **Web**: Exploit via HTTP request (direct exploitation)
- **Email**: Phishing with malicious attachment or link
- **Physical**: USB drop, physical access
- **Remote**: Direct network exploitation (SMB, RDP, SSH)
- **Supply Chain**: Compromise third-party dependency
- **Watering Hole**: Compromise frequently visited site

### 3. Delivery Plan
Populates `delivery-plan.md` with:

**Delivery Method**:
- Selected vector
- Justification (why this method?)
- Prerequisites (access, credentials, social engineering)

**Delivery Mechanism**:
- Technical implementation details
- Payload packaging (if applicable)
- Delivery infrastructure (redirectors, domains, servers)

**Delivery Execution**:
- Step-by-step delivery procedure
- Expected target behavior
- Success indicators
- Failure indicators

**OPSEC Considerations**:
- Attribution risks
- Detection likelihood
- Cleanup requirements

### 4. Delivery Execution
Guides through delivery execution:

**For Web Delivery**:
- Craft HTTP request with exploit payload
- Send request to target
- Monitor for callback or success indicator

**For Email Delivery**:
- Craft phishing email (if authorized)
- Attach or link to payload
- Send to target
- Monitor for execution

**For Remote Delivery**:
- Establish network connectivity to target
- Execute exploit against service
- Monitor for callback

### 5. Delivery Confirmation
Prompts for delivery status:
- Was payload delivered successfully?
- Did target receive/execute payload?
- Any errors or unexpected behavior?

Documents delivery outcome in `delivery/delivery-log.md`.

### 6. Gate Check
Validates:
- Delivery method documented
- Delivery execution logged
- Delivery outcome recorded (success/failure)
- Evidence captured (if applicable)

### 7. Next Steps
If delivery successful, suggests: `/engage.exploit`
If delivery failed, suggests: Review delivery plan and retry or select alternate vector

## Example Output

```
Starting Phase 3: Delivery

Reviewing weaponization output...
Target: CVE-2024-1234 (Nginx 1.21.0 RCE)
Payload: Linux x64 reverse shell (staged)
C2: attacker.example.com:443

Authorized delivery vectors (per ROE):
- Web (direct exploitation)
- Remote (network exploitation)

Recommended vector: Web (direct exploitation)
Target has exposed HTTP service on admin.acme-corp.com

Proceed with web delivery?
> Yes

Delivery Plan:
- Method: HTTP POST request to /api/upload
- Payload: Malicious file upload triggering buffer overflow
- Infrastructure: Direct connection (no redirector needed)
- Success indicator: HTTP 200 response + callback to C2

Executing delivery...

→ Crafting exploit request...
  Target: https://admin.acme-corp.com/api/upload
  Method: POST
  Payload size: 1847 bytes

→ Sending exploit request...
  Request sent at 2026-05-28 14:32:17 UTC
  Response: HTTP 200 OK
  Response time: 1.2s

→ Monitoring for callback...
  Listening on attacker.example.com:443
  Waiting for reverse shell connection...

  ✓ Callback received at 2026-05-28 14:32:19 UTC
  Source: 203.0.113.42:54321
  Connection established

Delivery successful!

Logging delivery outcome...
Evidence captured: delivery-evidence-20260528-143217.pcap

Running gate validation...

✓ Phase 3 (Delivery) gate validation PASSED
Ready to proceed to Phase 4 (Exploitation).
Run: /engage.exploit
```

## Available Skills

- `18-initial-access` — Phishing, payload delivery, HTML smuggling
- `03-exploit-development` — Exploit delivery mechanisms

## Notes

Delivery is the bridge between weaponization and exploitation. Ensure delivery method aligns with ROE and OPSEC requirements.
