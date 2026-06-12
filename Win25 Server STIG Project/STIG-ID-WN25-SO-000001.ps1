<#
.SYNOPSIS
    Sets LAN Manager authentication level to send NTLMv2 only and refuse LM and NTLM on Windows Server 2025.

.NOTES
    Author          : Santiago Abel Ruiz Diaz
    LinkedIn        : linkedin.com/in/santiago-a-ruiz-diaz-4aa418b2/
    GitHub          : github.com/Santi4g0RD
    Date Created    : 2026-06-12
    Last Modified   : 2026-06-12
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN25-SO-000001

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    Run with administrative privileges on Windows Server 2025.
    Example syntax:
    PS C:\> .\STIG-ID-WN25-SO-000001.ps1
#>

$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$valueName    = "LmCompatibilityLevel"
$valueData    = 5  # Send NTLMv2 only; refuse LM & NTLM

if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type DWord

Write-Host "LAN Manager authentication level set to 5 (NTLMv2 only — LM and NTLM refused)."
