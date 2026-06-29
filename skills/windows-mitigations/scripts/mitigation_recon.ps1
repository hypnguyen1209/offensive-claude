<#
.SYNOPSIS
    Fingerprint a Windows host mitigation landscape: VBS/HVCI/Credential Guard, WDAC/App Control,
    LSA Protection (PPL), AMSI provider state, ASR rules, kernel shadow stack, and system exploit
    mitigations. Maps each finding to a recommended attack strategy.

.DESCRIPTION
    Read-only recon. Run as admin for full coverage (some keys/WMI require it). For authorized
    engagement use only. Output is human-readable plus optional JSON for tooling.

.USAGE
    powershell -ExecutionPolicy Bypass -File mitigation_recon.ps1
    powershell -ExecutionPolicy Bypass -File mitigation_recon.ps1 -OutJson recon.json

.NOTES
    No external dependencies. Tested on Windows 10 21H2 .. Windows 11 24H2.
#>
[CmdletBinding()]
param([string]$OutJson)

$ErrorActionPreference = 'SilentlyContinue'
$report = [ordered]@{}

function Get-RegDword { param($Path,$Name) (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name }
function Note { param($Text) Write-Host ("  -> {0}" -f $Text) -ForegroundColor DarkGray }

Write-Host "=== Windows Mitigation Recon ===" -ForegroundColor Cyan
Write-Host ("Host: {0}  OS: {1}" -f $env:COMPUTERNAME, (Get-CimInstance Win32_OperatingSystem).Caption)

# --- VBS / HVCI / Credential Guard ---
$dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard
$vbs = [ordered]@{
    VbsStatus               = [int]$dg.VirtualizationBasedSecurityStatus
    HvciRunning             = ($dg.SecurityServicesRunning -contains 2)
    CredentialGuardRunning  = ($dg.SecurityServicesRunning -contains 1)
}
$report.VBS = $vbs
Write-Host "`n[VBS/HVCI/Credential Guard]" -ForegroundColor Yellow
Write-Host ("  VBS running              : {0}" -f ($vbs.VbsStatus -eq 2))
Write-Host ("  HVCI running             : {0}" -f $vbs.HvciRunning)
Write-Host ("  Credential Guard running : {0}" -f $vbs.CredentialGuardRunning)
if ($vbs.HvciRunning) { Note "BYOVD must use a signed driver; prefer data-only kernel edits (no unsigned kernel code)." }
else                  { Note "HVCI off: unsigned driver load is feasible." }
if ($vbs.CredentialGuardRunning) { Note "Credential Guard on: LSASS dump yields no protected secrets - use tickets/DCSync/DPAPI." }

# --- WDAC / App Control for Business ---
$ci = $null
try {
    $cig = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard
    $ci = [ordered]@{
        UserModeCI = [int]$cig.UsermodeCodeIntegrityPolicyEnforcementStatus  # 0 off,1 audit,2 enforced
        KernelCI   = [int]$cig.CodeIntegrityPolicyEnforcementStatus
    }
} catch {}
$report.WDAC = $ci
Write-Host "`n[WDAC / App Control for Business]" -ForegroundColor Yellow
if ($ci) {
    $map = @{0='Off';1='Audit';2='Enforced'}
    Write-Host ("  User-mode CI : {0}" -f $map[$ci.UserModeCI])
    Write-Host ("  Kernel CI    : {0}" -f $map[$ci.KernelCI])
    if ($ci.UserModeCI -eq 2) { Note "Enforced: use Microsoft-signed LOLBins / signed Electron(V8) / sideload into allowed images." }
    elseif ($ci.UserModeCI -eq 1) { Note "Audit only: execution allowed but logged (CodeIntegrity EID 3076)." }
}
# Probe for deployed policy file
if (Test-Path 'C:\Windows\System32\CodeIntegrity\SIPolicy.p7b') { Write-Host "  Deployed policy: SIPolicy.p7b present" }

# --- LSA Protection (PPL) ---
$runAsPPL = Get-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
$report.LSAProtection = @{ RunAsPPL = $runAsPPL }
Write-Host "`n[LSA Protection (PPL)]" -ForegroundColor Yellow
Write-Host ("  RunAsPPL : {0}" -f $(if ($null -eq $runAsPPL) {'Off'} else {$runAsPPL}))
if ($runAsPPL) { Note "LSASS is PPL-protected: use userland PPLmedic/PPLBlade/nanodump or BYOVD PPL-strip." }

# --- Kernel shadow stack (Win11 24H2 KMSSP) ---
$kss = Get-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks' 'Enabled'
$report.KernelShadowStack = @{ Enabled = $kss }
Write-Host "`n[Kernel Shadow Stack]" -ForegroundColor Yellow
Write-Host ("  KernelShadowStacks Enabled : {0}" -f $(if ($null -eq $kss) {'Not configured'} else {$kss}))
if ($kss) { Note "Kernel ROP blocked: use data-only kernel manipulation (no kernel ROP)." }

# --- ASR rules ---
$report.ASR = @{}
Write-Host "`n[ASR Rules]" -ForegroundColor Yellow
try {
    $pref = Get-MpPreference
    $ids = $pref.AttackSurfaceReductionRules_Ids
    $acts = $pref.AttackSurfaceReductionRules_Actions
    if ($ids) {
        for ($i=0; $i -lt $ids.Count; $i++) {
            $a = switch ($acts[$i]) {1{'Block'}2{'Audit'}6{'Warn'}default{'Off'}}
            Write-Host ("  {0} = {1}" -f $ids[$i], $a)
            $report.ASR[$ids[$i]] = $a
        }
        if ($ids -contains '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0') { Note "LSASS ASR rule present: dump from an existing excluded path or via trusted-image hollow." }
    } else { Write-Host "  No ASR rules configured." }
    if ($pref.ExclusionPath) {
        Write-Host "  Defender exclusion paths (apply to ALL ASR rules):"
        $pref.ExclusionPath | ForEach-Object { Write-Host ("    {0}" -f $_) }
        $report.ASR['_ExclusionPaths'] = @($pref.ExclusionPath)
    }
} catch { Write-Host "  Get-MpPreference unavailable (3rd-party AV or no Defender)." }

# --- AMSI provider state ---
Write-Host "`n[AMSI]" -ForegroundColor Yellow
$amsiProviders = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers' -ErrorAction SilentlyContinue
$report.AMSI = @{ Providers = @($amsiProviders.PSChildName) }
if ($amsiProviders) { $amsiProviders.PSChildName | ForEach-Object { Write-Host ("  Provider CLSID: {0}" -f $_) } }
else { Write-Host "  No AMSI providers registered." }

# --- System exploit mitigations (Exploit Protection) ---
Write-Host "`n[System Exploit Protection]" -ForegroundColor Yellow
try {
    $sys = Get-ProcessMitigation -System
    $report.SystemMitigation = @{
        DEP = $sys.Dep.Enable
        ASLR_BottomUp = $sys.Aslr.BottomUp
        ASLR_HighEntropy = $sys.Aslr.HighEntropy
        ASLR_ForceRelocate = $sys.Aslr.ForceRelocateImages
        CFG = $sys.Cfg.Enable
        UserShadowStack = $sys.UserShadowStack.UserShadowStack
    }
    Write-Host ("  DEP={0} ASLR(BU={1},HE={2},Force={3}) CFG={4} UserShadowStack(CET)={5}" -f `
        $sys.Dep.Enable, $sys.Aslr.BottomUp, $sys.Aslr.HighEntropy, $sys.Aslr.ForceRelocateImages, `
        $sys.Cfg.Enable, $sys.UserShadowStack.UserShadowStack)
} catch { Write-Host "  Get-ProcessMitigation -System unavailable." }

if ($OutJson) {
    $report | ConvertTo-Json -Depth 6 | Out-File -FilePath $OutJson -Encoding UTF8
    Write-Host ("`n[+] JSON written to {0}" -f $OutJson) -ForegroundColor Green
}
