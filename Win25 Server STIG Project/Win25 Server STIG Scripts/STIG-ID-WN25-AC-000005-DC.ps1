<#
.SYNOPSIS
    Sets account lockout duration to 15 minutes via Default Domain Policy on a Windows Server 2025 Domain Controller.

.NOTES
    Author          : Santiago Abel Ruiz Diaz
    LinkedIn        : linkedin.com/in/santiago-a-ruiz-diaz-4aa418b2/
    GitHub          : github.com/Santi4g0RD
    Date Created    : 2026-06-12
    Last Modified   : 2026-06-12
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
    Run with Domain Admin privileges on a Windows Server 2025 Domain Controller.
    Example syntax:
    PS C:\> .\STIG-ID-WN25-AC-000005-DC.ps1

.NOTES
    DC variant — uses Set-ADDefaultDomainPasswordPolicy instead of secedit.
    On a DC, secedit only affects local accounts; domain account lockout
    is controlled by Default Domain Policy.
#>

Import-Module ActiveDirectory

$domain = (Get-ADDomain).DNSRoot

Set-ADDefaultDomainPasswordPolicy -Identity $domain -LockoutDuration "00:15:00"

Write-Host "Account lockout duration set to 15 minutes on domain: $domain"
