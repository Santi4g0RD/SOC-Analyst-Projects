<#
.SYNOPSIS
    This PowerShell script sets the account lockout duration to 15 minutes or greater on Windows Server 2025.

.NOTES
    Author          : Santiago Abel Ruiz Diaz
    LinkedIn        : linkedin.com/in/
    GitHub          : github.com/
    Date Created    : 2026-06-10
    Last Modified   : 2026-06-10
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN25-AC-000005

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    Run with administrative privileges on Windows Server 2025.
    Example syntax:
    PS C:\> .\STIG-ID-WN25-AC-000005.ps1
#>

$tempFile = "$env:TEMP\secpol.cfg"

secedit /export /cfg $tempFile /quiet

$content = Get-Content $tempFile
$content = $content -replace "LockoutDuration\s*=\s*\d+", "LockoutDuration = 15"
$content | Set-Content $tempFile

secedit /configure /db "$env:TEMP\secpol.sdb" /cfg $tempFile /quiet

Remove-Item $tempFile -Force -ErrorAction SilentlyContinue

Write-Host "Account lockout duration set to 15 minutes."
