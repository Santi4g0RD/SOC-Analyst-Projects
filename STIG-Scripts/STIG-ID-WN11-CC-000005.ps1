<#
.SYNOPSIS
    This PowerShell script disables camera access from the lock screen.

.NOTES
    Author          : Santiago Abel Ruiz Diaz
    LinkedIn        : linkedin.com/in/
    GitHub          : github.com/
    Date Created    : 2026-06-10
    Last Modified   : 2026-06-10
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000005

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    Run with administrative privileges.
    Example syntax:
    PS C:\> .\STIG-ID-WN11-CC-000005.ps1
#>

$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
$valueName = "NoLockScreenCamera"
$valueData = 1

if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force
}

Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type DWord

Write-Host "Camera access from lock screen has been disabled."
