# Threat Hunt: TOR Browser Detection

<img width="595" height="265" alt="image" src="https://github.com/user-attachments/assets/32118673-fa6c-4186-8da8-db29206ac002" />

## Overview

A targeted threat hunt on a corporate Windows 11 workstation in response to management intelligence about anomalous encrypted outbound traffic and possible policy violations. The investigation confirmed unauthorized TOR browser installation, active circuit establishment to an external relay, and deliberate concealment of browsing artifacts.

**Environment:** Microsoft Defender for Endpoint (MDE)  
**Date of Activity:** May 26, 2026  
**Platform:** Azure — Windows 11 (`abel-win11-vm`)  
**Analyst:** Abel

---

## Environment

| Component | Details |
|---|---|
| EDR | Microsoft Defender for Endpoint (MDE) |
| Log Sources | DeviceFileEvents, DeviceProcessEvents, DeviceNetworkEvents |
| Endpoint | `abel-win11-vm` (Windows 11, Azure) |
| Subject Account | `lababel` |
| TOR Version | Portable TOR Browser 15.0.14 |

---

## Hunt Hypothesis

Management flagged anomalous encrypted outbound traffic and received anonymous reports of employees bypassing network controls. This hunt investigated whether any corporate endpoint had TOR browser installed or in active use.

**IoC scope:**
- `DeviceFileEvents` — TOR executable and configuration artifacts
- `DeviceProcessEvents` — installation and execution evidence
- `DeviceNetworkEvents` — outbound connections to known TOR relay ports

---

## Findings

### Installation — Portable Executable, Registry Evasion

At **10:38 AM on 2026-05-26**, the portable TOR Browser 15.0.14 installer was executed on `abel-win11-vm`. The user ran the portable variant from `C:\Users\lababel\Desktop\` rather than a standard installation path, deliberately bypassing the installer flow that would leave registry traces. File events captured multiple TOR components landing on the Desktop within the same minute: `Tor Browser.lnk`, `Tor Launcher.txt`, `Torbutton.txt`, `torbat`, and `icebuttom.bat`.

```kql
let TargetHostname = "abel-win11-vm";
DeviceFileEvents
| where DeviceName == TargetHostname
| where FileName has_any ("tor")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessCommandLine
| order by Timestamp desc
```

![DeviceFileEvents](assets/device-file-events.png)

**MITRE:** T1204 — User Execution, T1036 — Masquerading

---

### Execution and Circuit Establishment

At **10:38 AM**, `firefox.exe` (TOR Browser's browser engine) launched from `C:\Users\lababel\Desktop\`. The `portable` flag in the command line confirms the intent to avoid standard install-log traces. The TOR control port (`127.0.0.1:9151`) established immediately; the SOCKS proxy (`127.0.0.1:9150`) came online by **11:27 AM**. At **11:35 AM**, `tor.exe` completed a `ConnectionSuccess` to external relay `203.55.81.1` on port `9001` — a full TOR circuit confirmed.

```kql
let TargetHostname = "abel-win11-vm";
DeviceProcessEvents
| where DeviceName == TargetHostname
| where InitiatingProcessCommandLine has_any ("firefox.exe", "tor-browser.exe", "tor.exe")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessCommandLine
| order by Timestamp desc
```

![DeviceProcessEvents](assets/device-process-events.png)

```kql
let TargetHostname = "abel-win11-vm";
let TorPorts = dynamic([9001, 9030, 9040, 9050, 9051, 9150, 9151]);
DeviceNetworkEvents
| where DeviceName == TargetHostname
| where RemotePort in (TorPorts)
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

![DeviceNetworkEvents](assets/device-network-events.png)

**MITRE:** T1090.003 — Proxy: Multi-hop Proxy (TOR)

---

### Artifact Concealment — Indicator Removal

During the active TOR session, the file `tor-shopping-list.txt` was created on the Desktop and subsequently deleted. Combined with the portable installation method, this pattern indicates the user was aware of forensic artifacts and took deliberate steps to limit trace evidence.

**MITRE:** T1070 — Indicator Removal

---

## IOC Summary

| Type | Value |
|---|---|
| Endpoint | `abel-win11-vm` |
| Subject account | `lababel` |
| TOR binary | Portable TOR Browser 15.0.14 |
| Execution path | `C:\Users\lababel\Desktop\` |
| External relay | `203.55.81.1:9001` |
| Local SOCKS proxy | `127.0.0.1:9150` |
| Local control port | `127.0.0.1:9151` |
| Deleted artifact | `tor-shopping-list.txt` (Desktop) |

---

## Supporting Documentation

| Document | Description |
|---|---|
| [KQL Detection Queries](detection/kql-queries.md) | All queries used to surface TOR indicators across three MDE tables |
| [Findings Report](report/findings.md) | Full timeline, analysis, and escalation recommendation |

---

## MITRE ATT&CK Coverage

| Technique ID | Name | Tactic |
|---|---|---|
| T1090.003 | Proxy: Multi-hop Proxy (TOR) | Defense Evasion / C2 |
| T1204 | User Execution | Execution |
| T1036 | Masquerading | Defense Evasion |
| T1070 | Indicator Removal | Defense Evasion |
