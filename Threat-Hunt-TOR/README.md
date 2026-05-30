# Threat Hunt: TOR Browser Detection
<img width="595" height="265" alt="image" src="https://github.com/user-attachments/assets/32118673-fa6c-4186-8da8-db29206ac002" />

## Overview
This project detects unauthorized TOR browser installation and usage on a Windows 11 corporate
workstation (`abel-win11-vm`) using Microsoft Defender for Endpoint (MDE) and KQL queries.

## Scenario Summary
Management suspects employees may be using TOR browsers to bypass network security controls.
Recent network logs show unusual encrypted traffic patterns and connections to known TOR entry
nodes. Anonymous reports also suggest employees are discussing ways to access restricted sites
during work hours. The goal is to detect any TOR usage and notify management if confirmed.

## MITRE ATT&CK Coverage

| Technique ID | Name | Tactic |
|---|---|---|
| T1090.003 | Proxy: Multi-hop Proxy (TOR) | Defense Evasion / C2 |
| T1204 | User Execution | Execution |
| T1036 | Masquerading | Defense Evasion |

## Environment

| Component | Details |
|---|---|
| Victim VM | Windows 11 (`abel-win11-vm`) |
| EDR | Microsoft Defender for Endpoint (MDE) |
| Log Sources | DeviceFileEvents, DeviceProcessEvents, DeviceNetworkEvents |
| TOR Version | Portable TOR Browser 15.0.14 |

## Exercise Walkthrough

Follow each step below in order to see the full threat hunt from setup to final report:

| Step | Description | Link |
|---|---|---|
| 1 | Simulate TOR installation and usage as the bad actor | [Attack Simulation](attack-simulation/bad-actor-steps.md) |
| 2 | Run KQL queries in MDE Advanced Hunting to detect IoCs | [Detection Queries](detection/kql-queries.md) |
| 3 | Review full analysis, timeline, and conclusions | [Findings Report](report/findings.md) |
