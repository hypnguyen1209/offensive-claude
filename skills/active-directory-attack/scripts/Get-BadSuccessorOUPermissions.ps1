<#
.SYNOPSIS
    Get-BadSuccessorOUPermissions.ps1 - Enumerate OUs/containers where non-privileged
    principals can create dMSA objects (the BadSuccessor / CVE-2025-53779 precondition).

.DESCRIPTION
    BadSuccessor (Akamai, Yuval Gordon) only needs CreateChild over an OU plus the default
    CreatorOwner write rights to weaponize a delegated Managed Service Account. This script
    walks every OU and container, reads the DACL via ADSI/.NET DirectoryServices (no RSAT/AD
    module required), and reports ACEs that grant CreateChild (all child types, or specifically
    the msDS-DelegatedManagedServiceAccount class) to principals outside a default Tier-0 set.
    It also reports whether any Windows Server 2025 DC is present (the feature gate).

.PARAMETER Server
    Domain controller / domain DNS name to bind to. Defaults to the current domain.

.PARAMETER IncludeDefaultGroups
    Include built-in privileged groups (Domain Admins, Enterprise Admins, etc.) in output.
    Off by default so you see only the dangerous, non-Tier0 grants.

.EXAMPLE
    powershell -ep bypass -File .\Get-BadSuccessorOUPermissions.ps1
    powershell -ep bypass -File .\Get-BadSuccessorOUPermissions.ps1 -Server dc01.corp.local

.NOTES
    Read-only. Run as any domain user. Dependency: none (uses System.DirectoryServices).
    OPSEC: standard LDAP reads of OU security descriptors; blends with admin tooling.
#>
[CmdletBinding()]
param(
    [string]$Server,
    [switch]$IncludeDefaultGroups
)

$ErrorActionPreference = 'Stop'

# GUIDs
$DMSA_SCHEMA_GUID = [Guid]'7b8b558a-93a5-4af7-adca-c017e67f1057'  # msDS-DelegatedManagedServiceAccount class
$ALL_OBJECTS      = [Guid]'00000000-0000-0000-0000-000000000000'
$CREATE_CHILD     = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild

# Default Tier-0 principals to suppress unless -IncludeDefaultGroups
$Tier0 = @(
    'Domain Admins','Enterprise Admins','Administrators','SYSTEM',
    'Enterprise Domain Controllers','Domain Controllers','Account Operators',
    'BUILTIN\Administrators','NT AUTHORITY\SYSTEM','Schema Admins'
)

function Get-RootDSE {
    if ($Server) { return [ADSI]"LDAP://$Server/RootDSE" }
    return [ADSI]"LDAP://RootDSE"
}

$root = Get-RootDSE
$defaultNC = $root.defaultNamingContext
$bindPrefix = if ($Server) { "LDAP://$Server/" } else { "LDAP://" }
Write-Host "[+] Domain NC: $defaultNC" -ForegroundColor Cyan

# --- Server 2025 DC check (feature gate) -------------------------------------
$dcPath = "$bindPrefix" + "OU=Domain Controllers,$defaultNC"
$dcSearcher = [System.DirectoryServices.DirectorySearcher]::new(
    [ADSI]$dcPath, '(objectClass=computer)', @('dNSHostName','operatingSystem'))
$has2025 = $false
foreach ($r in $dcSearcher.FindAll()) {
    $os = [string]$r.Properties['operatingsystem']
    if ($os -match '2025') {
        $has2025 = $true
        Write-Host "[!] Windows Server 2025 DC present: $($r.Properties['dnshostname']) ($os)" -ForegroundColor Yellow
    }
}
if (-not $has2025) {
    Write-Host "[i] No Server 2025 DC detected - BadSuccessor not currently exploitable (still audit OU perms)." -ForegroundColor DarkGray
}

# --- Enumerate OUs + containers ----------------------------------------------
$searchRoot = [ADSI]("$bindPrefix$defaultNC")
$ouSearcher = [System.DirectoryServices.DirectorySearcher]::new(
    $searchRoot, '(|(objectClass=organizationalUnit)(objectClass=container))',
    @('distinguishedName'))
$ouSearcher.PageSize = 1000
$ouSearcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl

$findings = New-Object System.Collections.Generic.List[object]

foreach ($ou in $ouSearcher.FindAll()) {
    $dn = [string]$ou.Properties['distinguishedname']
    try {
        $de = [ADSI]("$bindPrefix$dn")
        $acl = $de.psbase.ObjectSecurity
    } catch { continue }

    foreach ($ace in $acl.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        if (-not ($ace.ActiveDirectoryRights -band $CREATE_CHILD)) { continue }

        # Either CreateChild for ALL object types, or specifically for dMSA class
        $isDmsaRelevant = ($ace.ObjectType -eq $ALL_OBJECTS) -or ($ace.ObjectType -eq $DMSA_SCHEMA_GUID)
        if (-not $isDmsaRelevant) { continue }

        $idn = $ace.IdentityReference.Value
        $shortName = ($idn -split '\\')[-1]
        if (-not $IncludeDefaultGroups -and ($Tier0 -contains $shortName -or $Tier0 -contains $idn)) {
            continue
        }

        $scope = if ($ace.ObjectType -eq $DMSA_SCHEMA_GUID) { 'dMSA-class only' } else { 'ALL child types' }
        $findings.Add([pscustomobject]@{
            Principal = $idn
            OU        = $dn
            Rights    = $ace.ActiveDirectoryRights.ToString()
            Scope     = $scope
            Inherited = $ace.IsInherited
        })
    }
}

Write-Host "`n=== Principals able to create dMSAs (BadSuccessor precondition) ===" -ForegroundColor Cyan
if ($findings.Count -eq 0) {
    Write-Host "  (none outside Tier-0 - good)" -ForegroundColor Green
} else {
    $findings | Sort-Object Principal | Format-Table -AutoSize
    Write-Host "[!] $($findings.Count) risky grant(s). Each lets that principal weaponize a dMSA." -ForegroundColor Red
    if ($has2025) {
        Write-Host "[!] Server 2025 DC present + these grants = exploitable. Patch CVE-2025-53779 and restrict OU ACLs." -ForegroundColor Red
    }
}
