<#
.SYNOPSIS
    Restricts "Take ownership of files or other objects" to Administrators only on Windows Server 2025.

.NOTES
    Author          : Santiago Abel Ruiz Diaz
    LinkedIn        : linkedin.com/in/santiago-a-ruiz-diaz-4aa418b2/
    GitHub          : github.com/Santi4g0RD
    Date Created    : 2026-06-12
    Last Modified   : 2026-06-12
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN25-UR-000035

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    Run with administrative privileges on Windows Server 2025.
    Example syntax:
    PS C:\> .\STIG-ID-WN25-UR-000035.ps1
#>

$tempCfg = "$env:TEMP\secpol_ur.cfg"
$tempSdb = "$env:TEMP\secpol_ur.sdb"

secedit /export /cfg $tempCfg /quiet

$content = Get-Content $tempCfg
# *S-1-5-32-544 = Administrators
$content = $content -replace "SeTakeOwnershipPrivilege\s*=.*", "SeTakeOwnershipPrivilege = *S-1-5-32-544"
$content | Set-Content $tempCfg

secedit /configure /db $tempSdb /cfg $tempCfg /quiet

Remove-Item $tempCfg -Force -ErrorAction SilentlyContinue
Remove-Item $tempSdb -Force -ErrorAction SilentlyContinue

Write-Host "SeTakeOwnershipPrivilege (Take ownership of files or objects) restricted to Administrators only."
