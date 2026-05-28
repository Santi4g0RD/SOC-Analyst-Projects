# KQL Hunting Queries — Microsoft Sentinel

All queries are run in Microsoft Sentinel → Logs.
Adjust the `ago()` time window to match when you ran the simulation.

---

## Query 1 — Scheduled Task Creation (T1053.005)

```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4698
| extend TaskName = tostring(EventData.TaskName)
| extend TaskContent = tostring(EventData.TaskContent)
| extend Account = tostring(EventData.SubjectUserName)
| project TimeGenerated, Computer, Account, TaskName, TaskContent
| order by TimeGenerated desc
```

**Expected result:** A row showing the scheduled task created by Atomic Red Team (typically named `Atomic Red Team`).

---

## Query 2 — Suspicious PowerShell Execution (T1059.001)

```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4688
| where Process has "powershell" or Process has "pwsh"
| extend CommandLine = tostring(EventData.CommandLine)
| extend ParentProcess = tostring(EventData.ParentProcessName)
| project TimeGenerated, Computer, Account, CommandLine, ParentProcess
| order by TimeGenerated desc
```

**Expected result:** PowerShell processes spawned during the simulation.

---

## Query 3 — Encoded PowerShell Commands (T1027)

```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4688
| extend CommandLine = tostring(EventData.CommandLine)
| where CommandLine has "-enc" 
    or CommandLine has "-encodedcommand" 
    or CommandLine has "-EncodedCommand"
| project TimeGenerated, Computer, Account, CommandLine
| order by TimeGenerated desc
```

**Expected result:** A process creation event with a base64-encoded command in the command line.

---

## Query 4 — Registry Run Key Modification (T1547.001) via Sysmon

```kql
Event
| where TimeGenerated > ago(1h)
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 13
| parse EventData with * '<Data Name="Image">' Image '</Data>' *
| parse EventData with * '<Data Name="TargetObject">' TargetObject '</Data>' *
| parse EventData with * '<Data Name="Details">' Details '</Data>' *
| where TargetObject has "CurrentVersion\\Run"
| project TimeGenerated, Computer, Image, TargetObject, Details
| order by TimeGenerated desc
```

**Expected result:** A registry write to `HKCU\...\CurrentVersion\Run` by the simulation process.

---

## Query 5 — PowerShell Script Block Logging (T1059.001 — deep visibility)

```kql
Event
| where TimeGenerated > ago(1h)
| where Source == "Microsoft-Windows-PowerShell"
| where EventID == 4104
| extend ScriptBlock = tostring(EventData)
| where ScriptBlock has "Invoke-Atomic" 
    or ScriptBlock has "schtasks" 
    or ScriptBlock has "New-ItemProperty"
| project TimeGenerated, Computer, ScriptBlock
| order by TimeGenerated desc
```

**Note:** Requires PowerShell Script Block Logging to be enabled via Group Policy.
Enable it with: `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging → EnableScriptBlockLogging = 1`

---

## Query 6 — Combined Attack Timeline

```kql
let timeframe = ago(2h);
let suspiciousProcesses = SecurityEvent
    | where TimeGenerated > timeframe
    | where EventID == 4688
    | where Process has "powershell" or Process has "schtasks"
    | extend Type = "ProcessCreate", Detail = tostring(EventData.CommandLine);
let scheduledTasks = SecurityEvent
    | where TimeGenerated > timeframe
    | where EventID == 4698
    | extend Type = "ScheduledTask", Detail = tostring(EventData.TaskName);
let registryPersistence = Event
    | where TimeGenerated > timeframe
    | where Source == "Microsoft-Windows-Sysmon"
    | where EventID == 13
    | parse EventData with * '<Data Name="TargetObject">' TargetObject '</Data>' *
    | parse EventData with * '<Data Name="Details">' Detail '</Data>' *
    | where TargetObject has "CurrentVersion\\Run"
    | extend Type = "RegistryRunKey";
union suspiciousProcesses, scheduledTasks, registryPersistence
| project TimeGenerated, Computer, Type, Detail
| order by TimeGenerated asc
```

**Expected result:** A chronological timeline of the full attack chain — process execution, scheduled task creation, and registry persistence — on the target VM.

---

## Query 7 — Sysmon Process Create (T1059.001 — deep visibility)

Sysmon Event ID 1 captures hashes and full parent command line — richer than SecurityEvent 4688.

```kql
Event
| where TimeGenerated > ago(1h)
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| parse EventData with * '<Data Name="Image">' Image '</Data>' *
| parse EventData with * '<Data Name="CommandLine">' CommandLine '</Data>' *
| parse EventData with * '<Data Name="ParentImage">' ParentImage '</Data>' *
| parse EventData with * '<Data Name="ParentCommandLine">' ParentCommandLine '</Data>' *
| parse EventData with * '<Data Name="Hashes">' Hashes '</Data>' *
| parse EventData with * '<Data Name="User">' User '</Data>' *
| where Image has "powershell" or Image has "pwsh" or Image has "schtasks" or Image has "cmd.exe"
| project TimeGenerated, Computer, User, Image, CommandLine, ParentImage, ParentCommandLine, Hashes
| order by TimeGenerated desc
```

**Expected result:** PowerShell and schtasks.exe processes with full command lines and SHA256 hashes for IOC correlation.

---

## Query 8 — Sysmon Network Connections (C2 detection)

```kql
Event
| where TimeGenerated > ago(1h)
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 3
| parse EventData with * '<Data Name="Image">' Image '</Data>' *
| parse EventData with * '<Data Name="DestinationIp">' DestinationIp '</Data>' *
| parse EventData with * '<Data Name="DestinationPort">' DestinationPort '</Data>' *
| parse EventData with * '<Data Name="DestinationHostname">' DestinationHostname '</Data>' *
| parse EventData with * '<Data Name="User">' User '</Data>' *
| where Image has "powershell" or Image has "pwsh" or Image has "wscript" or Image has "cscript"
| project TimeGenerated, Computer, User, Image, DestinationIp, DestinationPort, DestinationHostname
| order by TimeGenerated desc
```

**Expected result:** Any outbound connections made by PowerShell or script interpreters — relevant if the simulation payload makes a callback.

---

## Query 9 — Sysmon lsass Access (T1003 — Credential Access)

Monitors for processes opening a handle to lsass.exe, which is required for credential dumping tools like Mimikatz.

```kql
Event
| where TimeGenerated > ago(1h)
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 10
| parse EventData with * '<Data Name="SourceImage">' SourceImage '</Data>' *
| parse EventData with * '<Data Name="TargetImage">' TargetImage '</Data>' *
| parse EventData with * '<Data Name="GrantedAccess">' GrantedAccess '</Data>' *
| parse EventData with * '<Data Name="CallTrace">' CallTrace '</Data>' *
| where TargetImage has "lsass.exe"
| project TimeGenerated, Computer, SourceImage, TargetImage, GrantedAccess, CallTrace
| order by TimeGenerated desc
```

**Expected result:** Any non-system process accessing lsass.exe. High-fidelity alert — investigate any result.

---

## Query 10 — Sysmon File Create (Dropped Payloads)

```kql
Event
| where TimeGenerated > ago(1h)
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 11
| parse EventData with * '<Data Name="Image">' Image '</Data>' *
| parse EventData with * '<Data Name="TargetFilename">' TargetFilename '</Data>' *
| parse EventData with * '<Data Name="User">' User '</Data>' *
| where TargetFilename has "\\AppData\\" 
    or TargetFilename has "\\Temp\\"
    or TargetFilename endswith ".ps1"
    or TargetFilename endswith ".bat"
    or TargetFilename endswith ".vbs"
| project TimeGenerated, Computer, User, Image, TargetFilename
| order by TimeGenerated desc
```

**Expected result:** Any script files (.ps1, .bat, .vbs) written to disk or files dropped into AppData/Temp by the simulation.

---

## Sentinel Analytic Rules (Optional)
Create saved analytic rules in Sentinel → Analytics for continuous detection:
- Alert on any `EventID == 4698` (scheduled task creation)
- Alert on PowerShell with `-enc` in the command line
- Alert on registry writes to `CurrentVersion\Run`
- Alert on any process accessing `lsass.exe` (Sysmon Event ID 10)
