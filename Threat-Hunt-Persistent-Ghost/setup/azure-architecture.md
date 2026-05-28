# Azure Environment Setup

## Architecture

```
Azure Subscription
├── Resource Group: rg-threat-hunt
│   ├── Windows 11 VM (victim)
│   │   └── Azure Monitor Agent (AMA)
│   │   └── Sysmon
│   ├── Log Analytics Workspace
│   └── Microsoft Sentinel (enabled on workspace)
```

## Step 1 — Create Resource Group
1. Go to Azure Portal → Resource Groups → Create
2. Name: `rg-threat-hunt`
3. Region: choose your closest region

## Step 2 — Deploy Windows 11 VM
1. Azure Portal → Virtual Machines → Create
2. Image: `Windows 11 Pro`
3. Size: `Standard_B2s` (cost-effective for labs)
4. Allow RDP (port 3389) in the inbound rules — **restrict to your IP only**
5. Note the public IP after deployment

## Step 3 — Create Log Analytics Workspace
1. Azure Portal → Log Analytics Workspaces → Create
2. Name: `law-threat-hunt`
3. Same resource group and region as the VM

## Step 4 — Enable Microsoft Sentinel
1. Azure Portal → Microsoft Sentinel → Create
2. Select the `law-threat-hunt` workspace
3. Click Add

## Step 5 — Connect Windows Security Events
1. Sentinel → Content Hub → search "Windows Security Events"
2. Install the solution
3. Go to Data Connectors → "Windows Security Events via AMA"
4. Create a Data Collection Rule:
   - Target: your Windows 11 VM
   - Events: "All Security Events" (or Common for cost savings)

## Step 6 — Install Sysmon on the Windows 11 VM
RDP into the VM and run in PowerShell (as Administrator):

```powershell
# Download Sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"
Expand-Archive "$env:TEMP\Sysmon.zip" -DestinationPath "$env:TEMP\Sysmon"

# Copy config to Sysmon directory
Copy-Item "$PSScriptRoot\sysmon-config.xml" -Destination "$env:TEMP\Sysmon\sysmon-config.xml"

# Install with config
Set-Location "$env:TEMP\Sysmon"
.\Sysmon64.exe -accepteula -i .\sysmon-config.xml
```

Verify Sysmon is running and config is loaded:
```powershell
.\Sysmon64.exe -c
```

## Step 7 — Enable Audit Policies for Full Visibility
RDP into the VM and run in PowerShell (as Administrator):

```powershell
# Enable Process Command Line logging (required for Event ID 4688 to include command line)
auditpol /set /subcategory:"Process Creation" /success:enable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

# Enable PowerShell Script Block Logging (required for Event ID 4104)
$sbPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
If (-not (Test-Path $sbPath)) { New-Item -Path $sbPath -Force }
Set-ItemProperty -Path $sbPath -Name EnableScriptBlockLogging -Value 1

# Enable PowerShell Module Logging (Event ID 4103)
$mlPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
If (-not (Test-Path $mlPath)) { New-Item -Path $mlPath -Force }
Set-ItemProperty -Path $mlPath -Name EnableModuleLogging -Value 1
$mlModPath = "$mlPath\ModuleNames"
If (-not (Test-Path $mlModPath)) { New-Item -Path $mlModPath -Force }
Set-ItemProperty -Path $mlModPath -Name "*" -Value "*"
```

Verify the policies are applied:
```powershell
auditpol /get /subcategory:"Process Creation"
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
```

## Step 8 — Ingest Sysmon Logs into Sentinel
1. Sentinel → Data Connectors → search "Sysmon"
2. Or add a custom Windows Event log via AMA:
   - Channel: `Microsoft-Windows-Sysmon/Operational`

## Verification
Run these KQL queries in Sentinel to confirm all log sources are flowing:

```kql
// Windows Security Events (should include EventID 4688 with CommandLine populated)
SecurityEvent
| where TimeGenerated > ago(15m)
| summarize count() by Computer, EventID
| order by count_ desc
```

```kql
// Sysmon events (should show EventIDs 1, 3, 10, 11, 13)
Event
| where TimeGenerated > ago(15m)
| where Source == "Microsoft-Windows-Sysmon"
| summarize count() by Computer, EventID
| order by EventID asc
```

```kql
// PowerShell Script Block Logging (Event ID 4104 — confirms ScriptBlockLogging is active)
Event
| where TimeGenerated > ago(15m)
| where Source == "Microsoft-Windows-PowerShell"
| where EventID == 4104
| summarize count() by Computer
```
