# Threat Hunt: TOR Browser Detection
<img width="595" height="265" alt="image" src="https://github.com/user-attachments/assets/32118673-fa6c-4186-8da8-db29206ac002" />

## Overview
This project detects unauthorized TOR browser installation and usage on a Windows 11 corporate
workstation (`abel-win11-vm`) using Microsoft Defender for Endpoint (MDE) and KQL queries.

## Environment

| Component | Details |
|---|---|
| Victim VM | Windows 11 (`Microsoft Azure`) |
| EDR | Microsoft Defender for Endpoint (MDE) |
| KQL | Kusto Query Language |
| Log Sources | DeviceFileEvents, DeviceProcessEvents, DeviceNetworkEvents |
| TOR Version | Portable TOR Browser 15.0.14 |

## Scenario Summary
Management suspects employees may be using TOR browsers to bypass network security controls.
Recent network logs show unusual encrypted traffic patterns and connections to known TOR entry
nodes. Anonymous reports also suggest employees are discussing ways to access restricted sites
during work hours. The goal is to detect any TOR usage and notify management if confirmed.

### High-Level TOR-Related IoC Discovery Plan
- Check DeviceFileEvents for any `tor.exe` or `firefox.exe` file events.
- Check DeviceProcessEvents for any signs of installation or usage.
- Check DeviceNetworkEvents for any signs of outgoing connections over known TOR ports.

## Exercise Walkthrough

Follow each step below in order to see the full threat hunt from setup to final report:

| Step | Description | Link |
|---|---|---|
| 1 | Provision the VM and onboard to MDE | [Environment Setup](setup/environment-setup.md) |
| 2 | Simulate TOR installation and usage as the bad actor | [Attack Simulation](attack-simulation/bad-actor-steps.md) |
| 3 | Run KQL queries in MDE Advanced Hunting to detect IoCs | [Detection Queries](detection/kql-queries.md) |
| 4 | Review full analysis, timeline, and conclusions | [Findings Report](report/findings.md) |

## Summary

The user "lababel" on the "abel-win11-vm" device initiated and completed the installation of the TOR browser using a portable executable, deliberately bypassing standard installation paths to avoid leaving registry traces. They proceeded to launch the TOR browser, establish a full TOR circuit by connecting to an external relay node (`203.55.81.1` on port `9001`), and created various TOR-related files on their desktop, including a file named `tor-shopping-list.txt`. This file was subsequently deleted, indicating an attempt to conceal activity. This sequence of events confirms that the user actively installed, configured, and used the TOR browser — likely for anonymous browsing purposes — with the shopping list file suggesting possible intent to conduct transactions on the dark web.

## MITRE ATT&CK Coverage

| Technique ID | Name | Tactic |
|---|---|---|
| T1090.003 | Proxy: Multi-hop Proxy (TOR) | Defense Evasion / C2 |
| T1204 | User Execution | Execution |
| T1036 | Masquerading | Defense Evasion |

