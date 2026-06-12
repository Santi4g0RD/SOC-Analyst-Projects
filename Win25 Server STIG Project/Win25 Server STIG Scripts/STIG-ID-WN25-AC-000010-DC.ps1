<#
.SYNOPSIS
    Sets account lockout threshold to 3 invalid logon attempts via Default Domain Policy on a Windows Server 2025 Domain Controller.

.NOTES
    Author          : Santiago Abel Ruiz Diaz
    LinkedIn        : linkedin.com/in/santiago-a-ruiz-diaz-4aa418b2/
    GitHub          : github.com/Santi4g0RD
    Date Created    : 2026-06-12
    Last Modified   : 2026-06-12
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN25-AC-000010

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    Run with Domain Admin privileges on a Windows Server 2025 Domain Controller.
    Example syntax:
    PS C:\> .\STIG-ID-WN25-AC-000010-DC.ps1

.NOTES
    DC variant — uses Set-ADDefaultDomainPasswordPolicy instead of secedit.
#>

Import-Module ActiveDirectory

$domain = (Get-ADDomain).DNSRoot

Set-ADDefaultDomainPasswordPolicy -Identity $domain -LockoutThreshold 3

Write-Host "Account lockout threshold set to 3 invalid logon attempts on domain: $domain"
