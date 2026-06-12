<#
.SYNOPSIS
    Sets the reset account lockout counter to 15 minutes via Default Domain Policy on a Windows Server 2025 Domain Controller.

.NOTES
    Author          : Santiago Abel Ruiz Diaz
    LinkedIn        : linkedin.com/in/santiago-a-ruiz-diaz-4aa418b2/
    GitHub          : github.com/Santi4g0RD
    Date Created    : 2026-06-12
    Last Modified   : 2026-06-12
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
    Run with Domain Admin privileges on a Windows Server 2025 Domain Controller.
    Example syntax:
    PS C:\> .\STIG-ID-WN25-AC-000015-DC.ps1

.NOTES
    DC variant — uses Set-ADDefaultDomainPasswordPolicy instead of secedit.
#>

Import-Module ActiveDirectory

$domain = (Get-ADDomain).DNSRoot

Set-ADDefaultDomainPasswordPolicy -Identity $domain -LockoutObservationWindow "00:15:00"

Write-Host "Reset account lockout counter set to 15 minutes on domain: $domain"
