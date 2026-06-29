<#
.SYNOPSIS
    enum_boundaries.ps1 — Map the security-boundary posture of the current host so an
    operator can pick the right escape primitive (integrity, sandbox/AppContainer, PPL,
    BYOVD blocklist state, RPC/named-pipe surface).

.DESCRIPTION
    Read-only reconnaissance. Reports:
      * Current token integrity level, AppContainer membership, SeImpersonate/SeDebug.
      * VBS / HVCI / Credential Guard / LSA PPL (RunAsPPL) state.
      * Vulnerable-driver blocklist (DriverSiPolicy) enablement and last update.
      * PPL-protected processes (services.exe, lsass.exe, MsMpEng.exe, etc.).
      * Loaded kernel drivers from user-writable paths (BYOVD indicator).
      * Exposed named pipes (RPC/ALPC impersonation surface).

.USAGE
    powershell -ep bypass -File enum_boundaries.ps1            # full report
    powershell -ep bypass -File enum_boundaries.ps1 -Json      # machine-readable

.NOTES
    No admin required for most checks; some (driver list via Get-CimInstance) benefit
    from elevation. Pure WMI/registry/Win32 — no third-party deps. PS 5.1+ / PS7.
#>
[CmdletBinding()]
param([switch]$Json)

$ErrorActionPreference = 'SilentlyContinue'
$report = [ordered]@{}

# ---- 1. Token / integrity -------------------------------------------------
function Get-TokenPosture {
    $r = [ordered]@{}
    $r.User = whoami
    $groups = whoami /groups 2>$null
    $r.IntegrityLevel = ($groups | Select-String 'Mandatory Label\\(\w+)').Matches.Groups[1].Value
    $r.IsAppContainer = [bool]($groups | Select-String 'APPLICATION PACKAGE AUTHORITY|AppContainer|ALL APPLICATION PACKAGES')
    $priv = whoami /priv 2>$null
    $r.SeImpersonate = [bool]($priv | Select-String 'SeImpersonatePrivilege\s+\S+\s+Enabled')
    $r.SeDebug       = [bool]($priv | Select-String 'SeDebugPrivilege\s+\S+\s+Enabled')
    $r.SeAssignPrimaryToken = [bool]($priv | Select-String 'SeAssignPrimaryTokenPrivilege')
    return $r
}

# ---- 2. VBS / HVCI / Credential Guard / LSA PPL ---------------------------
function Get-VbsPosture {
    $r = [ordered]@{}
    $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard `
            -ClassName Win32_DeviceGuard
    if ($dg) {
        $r.VBS_Running          = ($dg.VirtualizationBasedSecurityStatus -eq 2)
        $r.HVCI_Running         = ($dg.SecurityServicesRunning -contains 2)
        $r.CredentialGuard_Run  = ($dg.SecurityServicesRunning -contains 1)
    }
    $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL
    $r.LSA_RunAsPPL = if ($null -ne $lsa.RunAsPPL) { $lsa.RunAsPPL } else { 0 }
    return $r
}

# ---- 3. Vulnerable-driver blocklist (BYOVD posture) -----------------------
function Get-DriverBlocklistPosture {
    $r = [ordered]@{}
    $ci = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' -Name VulnerableDriverBlocklistEnable
    $r.BlocklistEnabled = if ($null -ne $ci.VulnerableDriverBlocklistEnable) { [bool]$ci.VulnerableDriverBlocklistEnable } else { $false }
    $p7b = "$env:SystemRoot\System32\CodeIntegrity\driversipolicy.p7b"
    if (Test-Path $p7b) { $r.BlocklistFileDate = (Get-Item $p7b).LastWriteTime.ToString('s') }
    return $r
}

# ---- 4. PPL-protected processes -------------------------------------------
function Get-PplProcesses {
    # Protection level is not exposed by WMI; flag known-PPL candidates that are running.
    $targets = 'lsass','services','MsMpEng','csrss','wininit','smss','NisSrv','SecurityHealthService'
    Get-Process -Name $targets |
        Select-Object Name, Id, Path |
        ForEach-Object { [ordered]@{ Name=$_.Name; PID=$_.Id; Path=$_.Path } }
}

# ---- 5. Drivers loaded from user-writable paths (BYOVD red flag) ----------
function Get-SuspiciousDrivers {
    $writable = @($env:TEMP, $env:APPDATA, $env:LOCALAPPDATA, "$env:PUBLIC", "$env:USERPROFILE")
    Get-CimInstance Win32_SystemDriver |
        Where-Object { $_.State -eq 'Running' -and $_.PathName } |
        ForEach-Object {
            $path = ($_.PathName -replace '^\\\?\?\\','').Trim('"')
            if ($writable | Where-Object { $path -like "$_*" }) {
                [ordered]@{ Name=$_.Name; Path=$path; StartMode=$_.StartMode }
            }
        }
}

# ---- 6. Named-pipe surface (RPC/ALPC impersonation) -----------------------
function Get-NamedPipes {
    [System.IO.Directory]::GetFiles('\\.\pipe\') |
        ForEach-Object { ($_ -replace [regex]::Escape('\\.\pipe\'),'') } |
        Sort-Object -Unique
}

$report.Token            = Get-TokenPosture
$report.VBS              = Get-VbsPosture
$report.DriverBlocklist  = Get-DriverBlocklistPosture
$report.PplProcesses     = Get-PplProcesses
$report.SuspiciousDrivers= Get-SuspiciousDrivers
$report.NamedPipeCount   = (Get-NamedPipes).Count

if ($Json) {
    $report | ConvertTo-Json -Depth 6
    return
}

Write-Host "==== Windows Security-Boundary Posture ====" -ForegroundColor Cyan
Write-Host "`n[Token]"           ; $report.Token            | Format-List
Write-Host "[VBS / HVCI / PPL]"  ; $report.VBS              | Format-List
Write-Host "[Driver Blocklist]"  ; $report.DriverBlocklist  | Format-List
Write-Host "[PPL candidate procs]" ; $report.PplProcesses   | ForEach-Object { "{0,-22} PID={1}" -f $_.Name,$_.PID }
Write-Host "`n[Drivers from user-writable paths (BYOVD red flag)]"
if ($report.SuspiciousDrivers) { $report.SuspiciousDrivers | ForEach-Object { "  $($_.Name)  =>  $($_.Path)" } }
else { Write-Host "  (none)" }
Write-Host "`n[Named pipes exposed]: $($report.NamedPipeCount)"

Write-Host "`n---- Recommended escape primitive ----" -ForegroundColor Yellow
if ($report.Token.IsAppContainer) {
    Write-Host "  AppContainer/LPAC -> broker abuse or kernel bug (see sandbox-appcontainer-escape.md)"
} elseif ($report.Token.IntegrityLevel -eq 'Medium') {
    Write-Host "  Medium -> High: UAC bypass (integrity-uac-com.md)"
}
if ($report.Token.SeImpersonate) {
    Write-Host "  SeImpersonate present -> Potato / PhantomRPC to SYSTEM (rpc-alpc-boundary.md)"
}
if (-not $report.VBS.HVCI_Running -and -not $report.DriverBlocklist.BlocklistEnabled) {
    Write-Host "  HVCI off + blocklist off -> BYOVD kernel R/W viable (byovd-kernel-rw.md)"
} elseif ($report.VBS.HVCI_Running) {
    Write-Host "  HVCI ON -> BYOVD needs a non-blocklisted, HVCI-compatible driver"
}
if ($report.VBS.LSA_RunAsPPL -ge 1) {
    Write-Host "  LSASS is PPL -> use BYOVDLL / live-dump (ppl-protected-process.md)"
}
