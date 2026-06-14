#!/usr/bin/env powershell
#
# .SYNOPSIS
#     Adds a Windows Firewall inbound rule to allow the Nessus scan engine.
#
# .NOTES
#     Author          : Santiago Abel Ruiz Diaz
#     LinkedIn        : linkedin.com/in/santiago-a-ruiz-diaz-4aa418b2/
#     GitHub          : github.com/Santi4g0RD
#     Date Created    : 2026-06-14
#     Last Modified   : 2026-06-14
#     Version         : 1.0
#
# .USAGE
#     Run as Administrator before launching a Nessus scan.
#     Example syntax:
#     .\Allow-NessusScanEngine.ps1

$ScanEngineIP = "10.0.0.8"
$RuleName     = "Allow Nessus Scan Engine"

New-NetFirewallRule `
    -DisplayName $RuleName `
    -Direction Inbound `
    -RemoteAddress $ScanEngineIP `
    -Action Allow `
    -Protocol Any `
    -Profile Any `
    -Enabled True

Write-Host "Firewall rule '$RuleName' created — inbound traffic from $ScanEngineIP allowed."
