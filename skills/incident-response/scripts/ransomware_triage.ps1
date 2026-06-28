<#
.SYNOPSIS
  ransomware_triage.ps1 - Rapid Windows ransomware/extortion triage for IR scoping (read-mostly).

.DESCRIPTION
  Collects high-signal indicators to scope an active/suspected ransomware incident BEFORE
  eradication, aligned with 2025 TTPs (Scattered Spider/UNC3944, LockBit 5.0/DragonForce, and
  Velociraptor abuse CVE-2025-6264). Does NOT decrypt, reboot, or remove anything.

  Collects:
    - Volume Shadow Copy status (vssadmin) - were shadows deleted? (T1490)
    - Security/System log-clear events (1102/104) - anti-forensics
    - Ransom-note + ransomware-extension hits across drives
    - File-extension change burst from the USN journal (encryption window)
    - Recently created/modified services + scheduled tasks (persistence)
    - Suspect Velociraptor install (version vs 0.73.5 = CVE-2025-6264)
    - Backup-admin group membership additions (e.g. "Veeam Administrators")

.PARAMETER OutDir
  Output directory for the triage report and CSVs (use an off-host / clean path if possible).

.PARAMETER ScanPaths
  Roots to scan for ransom notes / encrypted extensions (default: all fixed drives).

.EXAMPLE
  powershell -ep bypass -File ransomware_triage.ps1 -OutDir C:\IR

.NOTES
  Run as Administrator. Capture RAM first (winpmem) on a live host. Assume the operator may be
  watching internal comms (UNC3944 joins IR bridges) - coordinate out-of-band.
#>
[CmdletBinding()]
param(
  [string]$OutDir = "$env:SystemDrive\IR_triage",
  [string[]]$ScanPaths,
  [int]$MaxNoteHits = 200
)

$ErrorActionPreference = 'SilentlyContinue'
$ts = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$OutDir = Join-Path $OutDir "ransom_triage_$ts"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$report = Join-Path $OutDir 'findings.txt'
function Flag([string]$sev,[string]$msg){ $line="[FLAG][$sev] $msg"; Write-Host $line; Add-Content $report $line }
function Info([string]$msg){ Write-Host "[INFO] $msg"; Add-Content $report "[INFO] $msg" }

Add-Content $report "=== Ransomware triage  host=$env:COMPUTERNAME  $ts ==="

if (-not $ScanPaths) {
  $ScanPaths = (Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -gt 0 }).Root
}

$ransomExt = @('*.lockbit','*.babuk','*.dragonforce','*.play','*.warlock','*.encrypted','*.locked','*.crypt')
$noteNames = @('*ransom*note*','*readme*decrypt*','*how_to_*decrypt*','*restore*files*','*_readme.txt','*decrypt*instructions*')

# 1) Shadow copy status (deleted shadows == T1490)
$vss = & vssadmin list shadows 2>&1
$vss | Out-File (Join-Path $OutDir 'vssadmin.txt')
if ($vss -match 'No items found' -or -not ($vss -match 'Shadow Copy ID')) {
  Flag 'HIGH' 'No Volume Shadow Copies present - possible vssadmin delete shadows (T1490 Inhibit Recovery)'
} else { Info 'Shadow copies present (good - candidate for recovery).' }

# 2) Log-clear events (anti-forensics)
foreach ($pair in @(@('Security',1102), @('System',104))) {
  $log=$pair[0]; $id=$pair[1]
  $ev = Get-WinEvent -FilterHashtable @{LogName=$log; Id=$id} -MaxEvents 5 2>$null
  if ($ev) {
    foreach ($e in $ev) { Flag 'HIGH' "Event $id ($log) log cleared at $($e.TimeCreated.ToUniversalTime())Z" }
    $ev | Select TimeCreated,Id,@{n='User';e={$_.UserId}} |
      Export-Csv (Join-Path $OutDir "logclear_$log.csv") -NoTypeInformation
  }
}

# 3) Ransom notes + encrypted-extension hits
$noteHits = foreach ($root in $ScanPaths) {
  Get-ChildItem -Path $root -Recurse -Include $noteNames -File -Force 2>$null |
    Select-Object FullName,Length,CreationTimeUtc,LastWriteTimeUtc
}
$noteHits | Select-Object -First $MaxNoteHits |
  Export-Csv (Join-Path $OutDir 'ransom_notes.csv') -NoTypeInformation
if ($noteHits) { Flag 'HIGH' ("Ransom note(s) found: {0} (see ransom_notes.csv)" -f @($noteHits).Count) }

$extHits = foreach ($root in $ScanPaths) {
  Get-ChildItem -Path $root -Recurse -Include $ransomExt -File -Force 2>$null |
    Select-Object FullName,Length,LastWriteTimeUtc
}
$extHits | Select-Object -First 1000 |
  Export-Csv (Join-Path $OutDir 'encrypted_files.csv') -NoTypeInformation
if ($extHits) { Flag 'HIGH' ("Files with ransomware extensions: {0} (encrypted_files.csv)" -f @($extHits).Count) }

# 4) USN extension-change burst (encryption window). Best-effort via fsutil.
$sys = $env:SystemDrive
$usn = & fsutil usn readjournal $sys csv 2>$null
if ($LASTEXITCODE -eq 0 -and $usn) {
  $usn | Out-File (Join-Path $OutDir 'usn_raw.csv')
  $renames = ($usn | Select-String 'RENAME|FILE_CREATE' | Measure-Object).Count
  Info "USN RENAME/FILE_CREATE records (recent): $renames (inspect usn_raw.csv for the burst window)"
} else { Info 'fsutil usn readjournal unavailable (journal may be cleared - itself an IOC).' }

# 5) Recently installed/modified services + scheduled tasks (persistence)
Get-CimInstance Win32_Service |
  Select-Object Name,DisplayName,PathName,StartMode,State,StartName |
  Export-Csv (Join-Path $OutDir 'services.csv') -NoTypeInformation
Get-ScheduledTask | ForEach-Object {
  [pscustomobject]@{
    TaskName=$_.TaskName; Path=$_.TaskPath; State=$_.State
    Action=($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join ' ; '
  }
} | Export-Csv (Join-Path $OutDir 'scheduled_tasks.csv') -NoTypeInformation
Info 'Enumerated services + scheduled tasks (review services.csv / scheduled_tasks.csv).'

# 6) Suspect Velociraptor (CVE-2025-6264 - abused as persistence, Talos/Storm-2603 Aug 2025)
$vrSvc = Get-CimInstance Win32_Service | Where-Object { $_.PathName -match 'velociraptor' }
$vrBin = Get-ChildItem -Path 'C:\Program Files','C:\ProgramData','C:\Windows\Temp' -Recurse `
  -Include 'velociraptor*.exe' -File -Force 2>$null | Select-Object -First 5
if ($vrSvc -or $vrBin) {
  Flag 'HIGH' 'Velociraptor present on host - verify it is YOUR deployment, not adversary persistence (CVE-2025-6264).'
  foreach ($b in $vrBin) {
    $v = (& $b.FullName version 2>$null | Select-String -Pattern '(\d+)\.(\d+)\.(\d+)').Matches.Value
    if ($v) {
      $parts = $v.Split('.') | ForEach-Object { [int]$_ }
      if (($parts[0] -lt 0) -or ($parts[0] -eq 0 -and ($parts[1] -lt 73 -or ($parts[1] -eq 73 -and $parts[2] -lt 5)))) {
        Flag 'HIGH' "Velociraptor $v at $($b.FullName) is < 0.73.5 -> CVE-2025-6264 vulnerable (abused build 0.73.4.0)."
      } else { Info "Velociraptor $v at $($b.FullName) (>=0.73.5)." }
    }
  }
}

# 7) Backup-admin abuse (operators add themselves to backup admins before encrypting)
foreach ($g in @('Veeam Administrators','Backup Operators','Administrators')) {
  $members = (Get-LocalGroupMember -Group $g 2>$null)
  if ($members) {
    $members | Select-Object Name,PrincipalSource |
      Export-Csv (Join-Path $OutDir ("group_" + ($g -replace '\s','_') + ".csv")) -NoTypeInformation
  }
}
Info 'Captured privileged/backup group membership (review group_*.csv for actor-added accounts).'

Write-Host ''
Write-Host "=== SUMMARY (full report: $report) ==="
$flags = Select-String -Path $report -Pattern '^\[FLAG\]'
if ($flags) {
  $flags | ForEach-Object { Write-Host $_.Line }
  Write-Host '[!] Active/likely ransomware indicators. PRESERVE (image + RAM) before eradication.'
  Write-Host '    Containment in PARALLEL: identity (disable+revoke), hypervisor (ESXi SSH/mgmt),'
  Write-Host '    backups (verify immutability). Coordinate IR on an OUT-OF-BAND channel.'
} else {
  Write-Host 'No strong ransomware indicators from these checks (absence != clean; correlate with EDR/timeline).'
}
Write-Host "Output: $OutDir"
