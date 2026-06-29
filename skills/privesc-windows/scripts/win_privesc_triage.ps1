<#
.SYNOPSIS
    win_privesc_triage.ps1 - Windows local privilege-escalation triage.

    Reads the current token (privileges, groups, integrity), classifies the privilege set, and
    prints the recommended escalation path + reference/tool. In -Quick mode it only does the token
    decision tree; full mode also enumerates high-value misconfigs (unquoted services, weak service
    ACLs, AlwaysInstallElevated, autologon creds, stored creds, scheduled tasks running as SYSTEM).

.USAGE
    powershell -ep bypass -File win_privesc_triage.ps1            # full triage
    powershell -ep bypass -File win_privesc_triage.ps1 -Quick     # token decision tree only

.NOTES
    Read-only / no payloads. Pure PowerShell, no external binaries (lower AV footprint than winPEAS).
    Works on PowerShell 5.1+ / 7. Run in the context whose privileges you want to assess.
    OPSEC: enumeration is read-only but voluminous; full mode touches many reg keys/services.
#>
[CmdletBinding()]
param([switch]$Quick)

$ErrorActionPreference = 'SilentlyContinue'
function H($t){ Write-Host "`n==== $t ====" -ForegroundColor Cyan }
function Win($t){ Write-Host "  [+] $t" -ForegroundColor Green }
function Hot($t){ Write-Host "  [!] $t" -ForegroundColor Yellow }

# ---- token: privileges, groups, integrity ----
H "IDENTITY"
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
Write-Host "  User: $($id.Name)   ($($id.User.Value))"
$adminSid = New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544'
$isAdminGroup = $id.Groups -contains $adminSid
$wp = New-Object Security.Principal.WindowsPrincipal $id
$isElevated  = $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "  In local Administrators group : $isAdminGroup"
Write-Host "  Effectively elevated (High IL): $isElevated"

# privileges via whoami /priv (enabled+disabled both matter for recovery)
$privText = (whoami /priv) -join "`n"
$privs = @()
foreach($line in (whoami /priv)){ if($line -match '(Se\w+Privilege)'){ $privs += $Matches[1] } }
H "TOKEN PRIVILEGES"
$privs | Sort-Object -Unique | ForEach-Object { Write-Host "  $_" }

$keyPrivs = @{
  SeImpersonatePrivilege        = 'Potato family -> SYSTEM (token-impersonation-potatoes.md)'
  SeAssignPrimaryTokenPrivilege = 'Potato / token swap -> SYSTEM (token-impersonation-potatoes.md)'
  SeDebugPrivilege              = 'Token theft + LSASS dump (credential-harvesting.md)'
  SeBackupPrivilege             = 'Read SAM/SYSTEM offline -> secretsdump (credential-harvesting.md)'
  SeRestorePrivilege            = 'Write protected files/registry -> service hijack (kernel-byovd.md)'
  SeTakeOwnershipPrivilege      = 'Own any object -> replace SYSTEM binary (kernel-byovd.md)'
  SeLoadDriverPrivilege         = 'BYOVD -> kernel (kernel-byovd.md)'
  SeManageVolumePrivilege       = 'Raw-disk read / arbitrary write (kernel-byovd.md)'
  SeTcbPrivilege                = 'Act as OS -> token forging (kernel-byovd.md)'
}

# ---- decision tree ----
H "RECOMMENDED PATH"
$matched = $false
foreach($p in $keyPrivs.Keys){
  if($privs -contains $p){ Hot "$p  ->  $($keyPrivs[$p])"; $matched = $true }
}
# Filtered service-account token? (Local/Network Service often strip SeImpersonate)
if($id.Name -match 'NETWORK SERVICE|LOCAL SERVICE' -and $privs -notcontains 'SeImpersonatePrivilege'){
  Hot "Filtered service token detected -> recover privileges with FullPowers, then Potato"
  $matched = $true
}
if($isAdminGroup -and -not $isElevated){
  Hot "Admin-group member at Medium IL + UAC -> UAC bypass to High (uac-bypass.md)"
  $matched = $true
}
if($isElevated){ Win "Already elevated -> BYOVD to kernel/PPL + credential harvest (kernel-byovd.md, credential-harvesting.md)" ; $matched=$true }
if(-not $matched){ Write-Host "  No privileged token rights -> hunt service/DLL/task/registry misconfig (service-dll-hijacking.md) or unpatched kernel CVE (kernel-byovd.md)" }

if($Quick){ return }

# ---- full enumeration of high-value misconfigs ----
H "OS / PATCH LEVEL"
$os = Get-CimInstance Win32_OperatingSystem
Write-Host "  $($os.Caption)  Build $($os.BuildNumber)"
Write-Host "  Latest hotfixes:"
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5 HotFixID,InstalledOn |
  ForEach-Object { Write-Host "    $($_.HotFixID)  $($_.InstalledOn)" }

H "UNQUOTED SERVICE PATHS (outside C:\Windows)"
Get-CimInstance Win32_Service | Where-Object {
  $_.PathName -and $_.PathName -notmatch '^\s*"' -and $_.PathName -match ' ' -and $_.PathName -notmatch '(?i)C:\\Windows'
} | ForEach-Object { Hot "$($_.Name) -> $($_.PathName)  [$($_.StartMode)]" }

H "WEAK SERVICE ACLS (Authenticated Users can change config)"
foreach($svc in (Get-CimInstance Win32_Service)){
  $sd = & sc.exe sdshow $svc.Name 2>$null
  if($sd -match 'A;;[^;]*(CCDC|WPRPWP|RPWPDTLO|SDRCWDWO|CCLCSWRPWPDTLOCRRC)[^;]*;;;(AU|WD|IU|BU)'){
    Hot "$($svc.Name) : potentially writable SDDL -> $sd"
  }
}

H "WRITABLE SERVICE BINARIES"
foreach($svc in (Get-CimInstance Win32_Service | Where-Object PathName)){
  $bin = ($svc.PathName -replace '^\s*"?([^"]+\.exe).*$','$1')
  if(Test-Path $bin){
    try {
      $acl = Get-Acl $bin
      foreach($ace in $acl.Access){
        if($ace.IdentityReference -match 'Everyone|Authenticated Users|Users|BUILTIN\\Users' -and
           $ace.FileSystemRights -match 'Write|Modify|FullControl' -and $ace.AccessControlType -eq 'Allow'){
          Hot "$($svc.Name): $bin writable by $($ace.IdentityReference)"; break
        }
      }
    } catch {}
  }
}

H "ALWAYSINSTALLELEVATED"
$hklm = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated).AlwaysInstallElevated
$hkcu = (Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated).AlwaysInstallElevated
if($hklm -eq 1 -and $hkcu -eq 1){ Hot "AlwaysInstallElevated=1 on BOTH hives -> SYSTEM via malicious MSI" }
else { Write-Host "  not exploitable (HKLM=$hklm HKCU=$hkcu)" }

H "AUTOLOGON / STORED CREDENTIALS"
$wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
if($wl.DefaultPassword){ Hot "Autologon: $($wl.DefaultUserName) / $($wl.DefaultPassword)" }
Write-Host "  cmdkey stored credentials:"; (cmdkey /list) | Where-Object { $_ -match 'Target|User' } | ForEach-Object { Write-Host "    $_" }

H "SCHEDULED TASKS RUNNING AS SYSTEM"
Get-ScheduledTask | Where-Object { $_.Principal.UserId -match 'SYSTEM' -and $_.State -ne 'Disabled' } |
  Select-Object -First 25 TaskName | ForEach-Object { Write-Host "  $($_.TaskName)" }

H "WRITABLE %PATH% ENTRIES (phantom DLL candidates)"
$env:PATH -split ';' | Where-Object { $_ } | ForEach-Object {
  $p = $_
  if(Test-Path $p){
    try{ $acl = Get-Acl $p
      if($acl.Access | Where-Object { $_.IdentityReference -match 'Everyone|Authenticated Users|BUILTIN\\Users' -and $_.FileSystemRights -match 'Write|Modify|FullControl' -and $_.AccessControlType -eq 'Allow' }){
        Hot "writable PATH dir: $p"
      }
    } catch {}
  }
}

Write-Host "`n[*] Triage complete. Follow the highlighted [!] items into the matching reference." -ForegroundColor Cyan
