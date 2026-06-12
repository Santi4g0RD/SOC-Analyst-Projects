<#
.SYNOPSIS
    This PowerShell script configures UAC to prompt administrators for credentials on the secure desktop on Windows Server 2025.

.NOTES
    Author          : Santiago Abel Ruiz Diaz
    LinkedIn        : linkedin.com/in/santiago-a-ruiz-diaz-4aa418b2/
    GitHub          : github.com/Santi4g0RD
    Date Created    : 2026-06-10
    Last Modified   : 2026-06-10
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN25-SO-000070

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    Run with administrative privileges on Windows Server 2025.
    Example syntax:
    PS C:\> .\STIG-ID-WN25-SO-000070.ps1
#>

$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$valueName = "ConsentPromptBehaviorAdmin"
$valueData = 1  # 1 = Prompt for credentials on secure desktop

if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force
}

Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type DWord

Write-Host "UAC set to prompt administrators for credentials on the secure desktop."
