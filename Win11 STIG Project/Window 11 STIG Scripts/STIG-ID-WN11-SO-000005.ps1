<#
.SYNOPSIS
    This PowerShell script disables the built-in Guest account on Windows 11.

.NOTES
    Author          : Santiago Abel Ruiz Diaz
    LinkedIn        : linkedin.com/in/santiago-a-ruiz-diaz-4aa418b2/
    GitHub          : github.com/Santi4g0RD
    Date Created    : 2026-06-10
    Last Modified   : 2026-06-10
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-SO-000005

.TESTED ON
    Date(s) Tested  : 2026-06-10
    Tested By       : Santiago Abel Ruiz Diaz
    Systems Tested  : Windows 11 (Azure VM)
    PowerShell Ver. : 5.1

.USAGE
    Run with administrative privileges.
    Example syntax:
    PS C:\> .\STIG-ID-WN11-SO-000005.ps1
#>

$guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue

if ($guestAccount) {
    Disable-LocalUser -Name "Guest"
    Write-Host "Guest account has been disabled."
} else {
    Write-Host "Guest account not found on this system."
}
