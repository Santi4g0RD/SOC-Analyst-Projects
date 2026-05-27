# Attack Simulation — Atomic Red Team

## Prerequisites
RDP into the Windows 11 VM and open PowerShell as Administrator.

## Install Atomic Red Team

```powershell
# Bypass execution policy for the session
Set-ExecutionPolicy Bypass -Scope Process -Force

# Install the framework
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force
```

---

## Technique 1 — PowerShell Execution (T1059.001)
Simulates an attacker running a PowerShell command, including an encoded (obfuscated) version.

```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 1
```

**What it does:** Executes a basic PowerShell payload and logs to Event ID 4688 / Sysmon Event ID 1.

---

## Technique 2 — Obfuscated Command (T1027)
Simulates base64-encoded PowerShell to evade simple string-based detection.

```powershell
Invoke-AtomicTest T1027 -TestNumbers 1
```

**What it does:** Runs `powershell.exe -enc <base64>`, which is a common attacker evasion technique.

---

## Technique 3 — Scheduled Task Persistence (T1053.005)
Creates a scheduled task that mimics malware persistence.

```powershell
Invoke-AtomicTest T1053.005 -TestNumbers 1
```

**What it does:** Creates a scheduled task via `schtasks.exe`. Logs to Event ID 4698.

---

## Technique 4 — Registry Run Key Persistence (T1547.001)
Adds an entry to the Registry Run key to survive reboots.

```powershell
Invoke-AtomicTest T1547.001 -TestNumbers 1
```

**What it does:** Writes to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`. Captured by Sysmon Event ID 13.

---

## Cleanup (after documentation)
Remove all artifacts created by the simulation:

```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup
Invoke-AtomicTest T1027 -TestNumbers 1 -Cleanup
Invoke-AtomicTest T1053.005 -TestNumbers 1 -Cleanup
Invoke-AtomicTest T1547.001 -TestNumbers 1 -Cleanup
```

---

## Evidence to Capture
- Screenshots of each `Invoke-AtomicTest` command running
- Screenshots of the scheduled task in Task Scheduler
- Screenshots of the registry key in regedit
- Sentinel alert screenshots (from `detection/kql-queries.md`)
