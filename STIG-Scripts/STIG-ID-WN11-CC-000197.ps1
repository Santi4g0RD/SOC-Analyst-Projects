<#
.SYNOPSIS
    This PowerShell script prevents Windows apps from being activated by voice while the system is locked.

.NOTES
    Author          : Santiago Abel Ruiz Diaz
    LinkedIn        : linkedin.com/in/
    GitHub          : github.com/
    Date Created    : 2026-06-10
    Last Modified   : 2026-06-10
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000197

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    Run with administrative privileges.
    Example syntax:
    PS C:\> .\STIG-ID-WN11-CC-000197.ps1
#>

$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
$valueName = "LetAppsActivateWithVoiceAboveLock"
$valueData = 2  # 2 = Force Deny

if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force
}

Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type DWord

Write-Host "Voice activation above the lock screen has been disabled."
