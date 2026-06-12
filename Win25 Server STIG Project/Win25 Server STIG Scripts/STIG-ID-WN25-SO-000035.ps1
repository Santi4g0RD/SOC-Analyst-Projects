<#
.SYNOPSIS
    Disables WDigest authentication to prevent plaintext credential caching on Windows Server 2025.

.NOTES
    Author          : Santiago Abel Ruiz Diaz
    LinkedIn        : linkedin.com/in/santiago-a-ruiz-diaz-4aa418b2/
    GitHub          : github.com/Santi4g0RD
    Date Created    : 2026-06-12
    Last Modified   : 2026-06-12
    Version         : 1.0
    CVEs            : CVE-2014-6321
    Plugin IDs      : N/A
    STIG-ID         : WN25-SO-000035

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    Run with administrative privileges on Windows Server 2025.
    Example syntax:
    PS C:\> .\STIG-ID-WN25-SO-000035.ps1
#>

$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
$valueName    = "UseLogonCredential"
$valueData    = 0  # 0 = WDigest disabled; credentials not stored in plaintext in LSASS

if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type DWord

Write-Host "WDigest authentication disabled (UseLogonCredential = 0) - plaintext credentials will not be cached in LSASS."
