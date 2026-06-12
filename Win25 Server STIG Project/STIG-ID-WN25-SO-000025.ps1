<#
.SYNOPSIS
    Configures NTLM to require NTLMv2 and 128-bit encryption for server sessions on Windows Server 2025.

.NOTES
    Author          : Santiago Abel Ruiz Diaz
    LinkedIn        : linkedin.com/in/santiago-a-ruiz-diaz-4aa418b2/
    GitHub          : github.com/Santi4g0RD
    Date Created    : 2026-06-12
    Last Modified   : 2026-06-12
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN25-SO-000025

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    Run with administrative privileges on Windows Server 2025.
    Example syntax:
    PS C:\> .\STIG-ID-WN25-SO-000025.ps1
#>

$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
$valueName    = "NtlmMinServerSec"
$valueData    = 537395200  # Require NTLMv2 + 128-bit encryption

if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type DWord

Write-Host "NTLM minimum server session security set to require NTLMv2 and 128-bit encryption (NtlmMinServerSec = 537395200)."
