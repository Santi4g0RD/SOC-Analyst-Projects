<#
.SYNOPSIS
    This PowerShell script configures UAC to prompt administrators for credentials on the secure desktop.

.NOTES
    Author          : Santiago Abel Ruiz Diaz
    LinkedIn        : linkedin.com/in/santiago-a-ruiz-diaz-4aa418b2/
    GitHub          : github.com/Santi4g0RD
    Date Created    : 2026-06-10
    Last Modified   : 2026-06-10
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-SO-000070

.TESTED ON
    Date(s) Tested  : 2026-06-10
    Tested By       : Santiago Abel Ruiz Diaz
    Systems Tested  : Windows 11 (Azure VM)
    PowerShell Ver. : 5.1

.USAGE
    Run with administrative privileges.
    Example syntax:
    PS C:\> .\STIG-ID-WN11-SO-000070.ps1
#>

$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

# ConsentPromptBehaviorAdmin = 1 means prompt for credentials on secure desktop
$valueName = "ConsentPromptBehaviorAdmin"
$valueData = 1

if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force
}

Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type DWord

Write-Host "UAC set to prompt administrators for credentials on the secure desktop."
