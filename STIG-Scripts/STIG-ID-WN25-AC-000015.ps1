<#
.SYNOPSIS
    This PowerShell script sets the reset account lockout counter to 15 minutes or greater on Windows Server 2025.

.NOTES
    Author          : Santiago Abel Ruiz Diaz
    LinkedIn        : linkedin.com/in/
    GitHub          : github.com/
    Date Created    : 2026-06-10
    Last Modified   : 2026-06-10
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN25-AC-000015

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    Run with administrative privileges on Windows Server 2025.
    Example syntax:
    PS C:\> .\STIG-ID-WN25-AC-000015.ps1
#>

$tempFile = "$env:TEMP\secpol.cfg"

secedit /export /cfg $tempFile /quiet

$content = Get-Content $tempFile
$content = $content -replace "ResetLockoutCount\s*=\s*\d+", "ResetLockoutCount = 15"
$content | Set-Content $tempFile

secedit /configure /db "$env:TEMP\secpol.sdb" /cfg $tempFile /quiet

Remove-Item $tempFile -Force -ErrorAction SilentlyContinue

Write-Host "Reset account lockout counter set to 15 minutes."
