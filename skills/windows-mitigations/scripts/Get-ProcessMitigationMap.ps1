<#
.SYNOPSIS
    Enumerate per-process exploit mitigations (CFG, DEP, ASLR, CET/UserShadowStack, ACG/Dynamic
    Code, CIG/Signature) and process protection level (PP/PPL), then rank processes from weakest
    (best pivot/target) to strongest. Helps pick a non-CET / non-ACG process to operate from.

.DESCRIPTION
    Read-only. Run as admin to read protection level of high-integrity/protected processes.
    For authorized engagement use only.

.USAGE
    powershell -ExecutionPolicy Bypass -File Get-ProcessMitigationMap.ps1
    powershell -ExecutionPolicy Bypass -File Get-ProcessMitigationMap.ps1 -Name chrome.exe
    powershell -ExecutionPolicy Bypass -File Get-ProcessMitigationMap.ps1 -WeakOnly -OutCsv map.csv

.NOTES
    Uses Get-ProcessMitigation (built-in). Protection level via native
    NtQueryInformationProcess(ProcessProtectionInformation) P/Invoke.
#>
[CmdletBinding()]
param(
    [string]$Name,
    [switch]$WeakOnly,
    [string]$OutCsv
)
$ErrorActionPreference = 'SilentlyContinue'

# --- P/Invoke to read PS_PROTECTION (PP/PPL) ---
$sig = @"
using System;
using System.Runtime.InteropServices;
public static class Native {
    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationProcess(IntPtr h, int cls, ref byte buf, int len, ref int ret);
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr h);
    public static int GetProtection(int pid) {
        IntPtr h = OpenProcess(0x1000 /*PROCESS_QUERY_LIMITED_INFORMATION*/, false, pid);
        if (h == IntPtr.Zero) return -1;
        byte b = 0; int ret = 0;
        int st = NtQueryInformationProcess(h, 61 /*ProcessProtectionInformation*/, ref b, 1, ref ret);
        CloseHandle(h);
        return st == 0 ? (int)b : -1;
    }
}
"@
try { Add-Type -TypeDefinition $sig -ErrorAction Stop } catch {}

function Decode-Protection([int]$b) {
    if ($b -lt 0) { return 'n/a' }
    if ($b -eq 0) { return 'None' }
    $type = $b -band 0x07
    $signer = ($b -shr 4) -band 0x0F
    $t = @{1='PPL';2='PP'}[$type]; if (-not $t) { $t = "T$type" }
    $s = @{0='None';1='Authenticode';2='CodeGen';3='Antimalware';4='Lsa';5='Windows';6='WinTcb';7='WinSystem'}[$signer]
    return "$t-$s"
}

$procs = if ($Name) { Get-Process -Name ([IO.Path]::GetFileNameWithoutExtension($Name)) } else { Get-Process }
$rows = foreach ($p in $procs) {
    $m = Get-ProcessMitigation -Id $p.Id -ErrorAction SilentlyContinue
    if (-not $m) { continue }
    $cet = $m.UserShadowStack.UserShadowStack
    $cfg = $m.Cfg.Enable
    $acg = $m.DynamicCode.ProhibitDynamicCode
    $cig = $m.ImageLoad.BlockNonMicrosoftSigned -or $m.ImageLoad.MicrosoftSignedOnly
    $aslrHE = $m.Aslr.HighEntropy
    $prot = Decode-Protection ([Native]::GetProtection($p.Id))

    # Weakness score: higher = weaker = better pivot/target. Missing each mitigation +1.
    $score = 0
    if ($cet -ne 'ON' -and $cet -ne $true) { $score++ }
    if ($cfg -ne 'ON' -and $cfg -ne $true) { $score++ }
    if ($acg -ne 'ON' -and $acg -ne $true) { $score++ }
    if (-not $cig) { $score++ }
    if ($aslrHE -ne 'ON' -and $aslrHE -ne $true) { $score++ }

    [pscustomobject]@{
        PID        = $p.Id
        Name       = $p.ProcessName
        CET        = [string]$cet
        CFG        = [string]$cfg
        ACG        = [string]$acg
        CIG        = [bool]$cig
        ASLR_HE    = [string]$aslrHE
        Protection = $prot
        WeakScore  = $score
    }
}

$rows = $rows | Sort-Object WeakScore -Descending
if ($WeakOnly) { $rows = $rows | Where-Object { $_.WeakScore -ge 3 } }

$rows | Format-Table -AutoSize
Write-Host "`nWeakScore: count of MISSING mitigations (CET,CFG,ACG,CIG,ASLR_HE). Higher = better pivot/target." -ForegroundColor DarkGray
Write-Host "Protection: PP/PPL signer level (Antimalware = EDR; Lsa = LSA Protection)." -ForegroundColor DarkGray

if ($OutCsv) { $rows | Export-Csv -NoTypeInformation -Path $OutCsv; Write-Host "[+] CSV -> $OutCsv" -ForegroundColor Green }
