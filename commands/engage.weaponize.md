---
description: Execute Phase 2 - Weaponization and Payload Development
---

# /engage.weaponize

Executes Phase 2 (Weaponization) of the engagement workflow.

## Usage

`/engage.weaponize [--target <vulnerability>] [--payload-type <type>]`

Options:
- `--target`: Specify target vulnerability (CVE or description)
- `--payload-type`: Specify payload type (shell, implant, exploit)

## Process

### 1. Load Templates
Loads:
- `weaponize/exploit-blueprint.md` — Exploit design document
- `weaponize/payload-config.md` — Payload configuration

### 2. Target Selection
Reviews reconnaissance output and prompts:
- Which vulnerability or weakness to target?
- What is the exploitation goal? (initial access, privilege escalation, lateral movement)
- What are the target constraints? (OS, architecture, mitigations)

### 3. Exploit Design
Populates `exploit-blueprint.md` with:

**Vulnerability Analysis**:
- CVE/CWE identification
- Vulnerability type (RCE, SQLi, XSS, etc.)
- Affected versions
- Public exploits available?

**Exploitation Strategy**:
- Attack vector (network, web, client-side)
- Exploitation technique
- Mitigation bypass requirements (ASLR, DEP, CFG, SMEP/SMAP)
- Reliability assessment

**Payload Requirements**:
- Payload type (reverse shell, bind shell, implant, dropper)
- Encoding/obfuscation needs
- Size constraints
- Persistence requirements

### 4. Payload Configuration
Populates `payload-config.md` with:

**Payload Specifications**:
- Payload format (ELF, PE, shellcode, script)
- Architecture (x86, x64, ARM)
- Delivery method (staged, stageless)

**C2 Configuration**:
- Callback IP/domain
- Callback port and protocol
- Encryption/encoding
- Beacon interval

**Evasion Techniques**:
- AV/EDR evasion methods
- Obfuscation techniques
- AMSI bypass (if Windows PowerShell)
- ETW patching (if Windows)

**OPSEC Considerations**:
- Attribution concerns
- Network indicators
- Host artifacts
- Cleanup requirements

### 5. Payload Development
Offers to invoke relevant skills:
- `03-exploit-development` — PoC and payload crafting
- `17-edr-evasion` — AV/EDR bypass techniques
- `19-shellcode-dev` — Shellcode development
- `20-windows-mitigations` — Mitigation bypass (ASLR/DEP/CFG)

### 6. Gate Check
Validates:
- Target vulnerability selected and documented
- Payload type chosen
- Mitigation bypass strategy documented (if applicable)
- C2 configuration specified
- OPSEC considerations addressed

### 7. Next Steps
If gate passes, suggests: `/engage.deliver` or `/engage.exploit` (depending on workflow)

## Example Output

```
Starting Phase 2: Weaponization

Reviewing reconnaissance findings...
Found 3 potential targets:
1. CVE-2024-1234 - Nginx 1.21.0 RCE (admin.acme-corp.com)
2. Exposed RDP - Windows Server 2019 (rdp.acme-corp.com)
3. Outdated WordPress - Multiple plugins (blog.acme-corp.com)

Which target would you like to weaponize?
> 1

Target: CVE-2024-1234 (Nginx 1.21.0 RCE)
Exploitation goal?
> Initial access to web server

Designing exploit...

Vulnerability Analysis:
- CVE-2024-1234: Buffer overflow in Nginx request parsing
- Affects: Nginx 1.21.0 - 1.21.3
- Public exploit: Yes (Metasploit module available)
- Reliability: High (90%+ success rate)

Exploitation Strategy:
- Attack vector: Network (HTTP request)
- Technique: Stack buffer overflow → RIP control
- Mitigations present: ASLR, NX/DEP
- Bypass: Information leak + ROP chain

Payload Requirements:
- Type: Reverse shell (staged)
- Format: Linux x64 shellcode
- Size constraint: 2048 bytes max
- Persistence: Not required for initial access

C2 Configuration:
What is your callback IP/domain?
> attacker.example.com

Callback port?
> 443

Payload configuration complete.

OPSEC Considerations:
- Network indicator: HTTPS callback to attacker.example.com
- Host artifact: /tmp/.shell socket file
- Recommendation: Use domain fronting or redirector

Weaponization complete.
Running gate validation...

✓ Phase 2 (Weaponization) gate validation PASSED
Ready to proceed to Phase 3 (Delivery).
Run: /engage.deliver
```

## Available Skills

- `03-exploit-development` — PoC development and payload crafting
- `17-edr-evasion` — EDR/AV bypass techniques
- `19-shellcode-dev` — Shellcode development and loaders
- `20-windows-mitigations` — Exploit mitigation bypass

## Notes

Proper weaponization considers target environment, mitigations, and OPSEC. Always test payloads in a lab environment before deployment.
