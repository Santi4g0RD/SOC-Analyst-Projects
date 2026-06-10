<#
.SYNOPSIS
    This PowerShell script disables the built-in Guest account on Windows 11.

.NOTES
    Author          : Santiago Abel Ruiz Diaz
    LinkedIn        : linkedin.com/in/
    GitHub          : github.com/
    Date Created    : 2026-06-10
    Last Modified   : 2026-06-10
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-SO-000005

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

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
