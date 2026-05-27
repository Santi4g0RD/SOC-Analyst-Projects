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

# Install with config
cd "$env:TEMP\Sysmon"
.\Sysmon64.exe -accepteula -i
```

Use the `sysmon-config.xml` in this folder for a more complete configuration.

## Step 7 — Ingest Sysmon Logs into Sentinel
1. Sentinel → Data Connectors → search "Sysmon"
2. Or add a custom Windows Event log via AMA:
   - Channel: `Microsoft-Windows-Sysmon/Operational`

## Verification
Run this KQL in Sentinel to confirm logs are flowing:

```kql
SecurityEvent
| where TimeGenerated > ago(15m)
| summarize count() by Computer, EventID
| order by count_ desc
```
