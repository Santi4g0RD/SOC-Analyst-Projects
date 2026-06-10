<#
.SYNOPSIS
    This PowerShell script sets the account lockout duration to 15 minutes or greater.

.NOTES
    Author          : Santiago Abel Ruiz Diaz
    LinkedIn        : linkedin.com/in/santiago-a-ruiz-diaz-4aa418b2/
    GitHub          : github.com/Santi4g0RD
    Date Created    : 2026-06-10
    Last Modified   : 2026-06-10
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AC-000005

.TESTED ON
    Date(s) Tested  : 2026-06-10
    Tested By       : Santiago Abel Ruiz Diaz
    Systems Tested  : Windows 11 (Azure VM)
    PowerShell Ver. : 5.1

.USAGE
    Run with administrative privileges.
    Example syntax:
    PS C:\> .\
#>

$tempFile = "$env:TEMP\secpol.cfg"

secedit /export /cfg $tempFile /quiet

$content = Get-Content $tempFile
$content = $content -replace "LockoutDuration\s*=\s*\d+", "LockoutDuration = 15"
$content | Set-Content $tempFile

secedit /configure /db "$env:TEMP\secpol.sdb" /cfg $tempFile /quiet

Remove-Item $tempFile -Force -ErrorAction SilentlyContinue

Write-Host "Account lockout duration set to 15 minutes."
