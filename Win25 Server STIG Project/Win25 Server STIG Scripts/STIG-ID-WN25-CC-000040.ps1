<#
.SYNOPSIS
    This PowerShell script disables the SMBv1 protocol on Windows Server 2025.

.NOTES
    Author          : Santiago Abel Ruiz Diaz
    LinkedIn        : linkedin.com/in/santiago-a-ruiz-diaz-4aa418b2/
    GitHub          : github.com/Santi4g0RD
    Date Created    : 2026-06-10
    Last Modified   : 2026-06-10
    Version         : 1.0
    CVEs            : CVE-2017-0144 (EternalBlue/WannaCry)
    Plugin IDs      : N/A
    STIG-ID         : WN25-CC-000040

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    Run with administrative privileges on Windows Server 2025.
    Example syntax:
    PS C:\> .\STIG-ID-WN25-CC-000040.ps1
#>

Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

Write-Host "SMBv1 protocol has been disabled."
