# Threat Hunt: Operation Persistent Ghost

## Overview
This project simulates a malware execution and persistence scenario on a Windows 11 Azure VM,
detected and investigated using Microsoft Sentinel.

## Scenario Summary
An attacker gains initial access and executes a PowerShell payload, then establishes persistence
via a Scheduled Task and a Registry Run key. The goal is to detect, hunt, and document these
techniques using Sentinel KQL queries.

## MITRE ATT&CK Coverage

| Technique ID | Name | Tactic |
|---|---|---|
| T1059.001 | PowerShell | Execution |
| T1053.005 | Scheduled Task | Persistence |
| T1547.001 | Registry Run Keys | Persistence |
| T1027 | Obfuscated Files or Information | Defense Evasion |

## Environment

| Component | Details |
|---|---|
| Victim VM | Windows 11 (Azure) |
| SIEM | Microsoft Sentinel |
| Log Source | Windows Security Events + Sysmon via AMA |
| Simulation Tool | Atomic Red Team |

## Project Structure

```
Threat-Hunt-Persistent-Ghost/
├── README.md
├── setup/
│   ├── azure-architecture.md       # VM and Sentinel setup steps
│   └── sysmon-config.xml           # Sysmon configuration used
├── attack-simulation/
│   └── atomic-red-team-steps.md    # Attack steps with Atomic Red Team
├── detection/
│   └── kql-queries.md              # KQL hunting queries + results
└── report/
    └── findings.md                 # Analysis and MITRE mapping
```

## How to Reproduce
1. Follow `setup/azure-architecture.md` to deploy the environment
2. Run the attack simulation from `attack-simulation/atomic-red-team-steps.md`
3. Execute the KQL queries in `detection/kql-queries.md` inside Microsoft Sentinel
4. Review findings in `report/findings.md`
