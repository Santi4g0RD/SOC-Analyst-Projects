<#
.SYNOPSIS
    Disables NetBIOS over TCP/IP on all active network adapters on Windows Server 2025.

.NOTES
    Author          : Santiago Abel Ruiz Diaz
    LinkedIn        : linkedin.com/in/santiago-a-ruiz-diaz-4aa418b2/
    GitHub          : github.com/Santi4g0RD
    Date Created    : 2026-06-12
    Last Modified   : 2026-06-12
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN25-NE-000010

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    Run with administrative privileges on Windows Server 2025.
    Example syntax:
    PS C:\> .\STIG-ID-WN25-NE-000010.ps1
#>

$adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"

foreach ($adapter in $adapters) {
    # SetTcpipNetbios: 0=default (DHCP), 1=enable, 2=disable
    $result = $adapter.SetTcpipNetbios(2)
    if ($result.ReturnValue -eq 0) {
        Write-Host "NetBIOS over TCP/IP disabled on adapter: $($adapter.Description)"
    } else {
        Write-Host "Failed to disable NetBIOS on adapter: $($adapter.Description) (return code: $($result.ReturnValue))"
    }
}
