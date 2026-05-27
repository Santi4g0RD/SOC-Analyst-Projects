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
| extend EventXml = parse_xml(EventData)
| extend TargetObject = tostring(EventXml.DataItem.TargetObject)
| extend Details = tostring(EventXml.DataItem.Details)
| extend Image = tostring(EventXml.DataItem.Image)
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
union suspiciousProcesses, scheduledTasks
| project TimeGenerated, Computer, Type, Detail
| order by TimeGenerated asc
```

**Expected result:** A chronological timeline of the full attack chain on the target VM.

---

## Sentinel Analytic Rules (Optional)
Create saved analytic rules in Sentinel → Analytics for continuous detection:
- Alert on any `EventID == 4698` (scheduled task creation)
- Alert on PowerShell with `-enc` in the command line
- Alert on registry writes to `CurrentVersion\Run`
