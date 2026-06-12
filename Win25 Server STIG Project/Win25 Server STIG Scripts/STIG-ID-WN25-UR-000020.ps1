<#
.SYNOPSIS
    Ensures the Guest account is denied the "Log on as a service" right on Windows Server 2025.

.NOTES
    Author          : Santiago Abel Ruiz Diaz
    LinkedIn        : linkedin.com/in/santiago-a-ruiz-diaz-4aa418b2/
    GitHub          : github.com/Santi4g0RD
    Date Created    : 2026-06-12
    Last Modified   : 2026-06-12
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN25-UR-000020

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    Run with administrative privileges on Windows Server 2025.
    Example syntax:
    PS C:\> .\STIG-ID-WN25-UR-000020.ps1
#>

$tempCfg = "$env:TEMP\secpol_ur.cfg"
$tempSdb = "$env:TEMP\secpol_ur.sdb"

secedit /export /cfg $tempCfg /quiet

$content = Get-Content $tempCfg
$guestsSid = "*S-1-5-32-546"

if ($content -match "SeDenyServiceLogonRight\s*=\s*(.*)") {
    $existing = $Matches[1].Trim()
    if ($existing -notmatch [regex]::Escape($guestsSid)) {
        $newVal = if ($existing -eq "") { $guestsSid } else { "$existing,$guestsSid" }
        $content = $content -replace "SeDenyServiceLogonRight\s*=.*", "SeDenyServiceLogonRight = $newVal"
    }
} else {
    $content += "`r`nSeDenyServiceLogonRight = $guestsSid"
}

$content | Set-Content $tempCfg

secedit /configure /db $tempSdb /cfg $tempCfg /quiet

Remove-Item $tempCfg -Force -ErrorAction SilentlyContinue
Remove-Item $tempSdb -Force -ErrorAction SilentlyContinue

Write-Host "SeDenyServiceLogonRight - Guests denied log on as a service."
