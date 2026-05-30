# KQL Detection Queries

All queries target device: `abel-win11-vm`

---

## 1. DeviceFileEvents — TOR File Artifacts

**Goal:** Find any files whose name contains "tor" to identify TOR installation artifacts.

```kql
let TargetHostname = "abel-win11-vm";
DeviceFileEvents
| where DeviceName == TargetHostname
| where FileName has_any ("tor")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Findings

| File | Significance |
|---|---|
| `Tor Browser.lnk` | Shortcut created — TOR Browser was installed |
| `torbat` | TOR-related batch/config file |
| `icebuttom.bat` | Possibly a TOR launcher script |
| `Tor Launcher.txt` | TOR launcher component |
| `tor-shopping-list.txt` | Suspicious — suggests intentional dark web activity |
| `torbox.txt` | TOR-related config or reference file |
| `Torbutton.txt` | TOR Browser extension component |

Most events are `FileCreated` with paths under `C:\Users\labuser\Desktop\`, confirming the user
actively placed TOR-related files on their desktop.

All events cluster around **May 26, 2026, 10:38 AM – 1:29 PM**.

![DeviceFileEvents results](../assets/device-file-events.png)

---

## 2. DeviceProcessEvents — TOR Execution Confirmation

**Goal:** Confirm whether TOR was actually executed, not just installed.

```kql
let TargetHostname = "abel-win11-vm";
DeviceProcessEvents
| where DeviceName == TargetHostname
| where InitiatingProcessCommandLine has_any ("firefox.exe", "tor-browser.exe", "tor.exe")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Findings

| Field | Value |
|---|---|
| Timestamp | May 26, 2026, 10:38:24 AM |
| Device | `abel-win11-vm` |
| Action | `ProcessCreated` |
| File Executed | `firefox.exe` |
| Folder Path | `C:\Users\lababel\Desktop\` |
| SHA256 | `51534655250d77...` |

`firefox.exe` launched from `C:\Users\lababel\Desktop\` (outside normal Program Files) confirms
TOR Browser execution. The `portable` flag in the command line shows the user deliberately avoided
standard install locations to reduce traces.

![DeviceProcessEvents results](../assets/device-process-events.png)

---

## 3. DeviceNetworkEvents — TOR Network Connections

**Goal:** Confirm TOR established real outbound connections via known TOR ports.

```kql
let TargetHostname = "abel-win11-vm";
let TorPorts = dynamic([9001, 9030, 9040, 9050, 9051, 9150, 9151]);
DeviceNetworkEvents
| where DeviceName == TargetHostname
| where RemotePort in (TorPorts)
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Findings

| Timestamp | Action | Remote IP | Port | Process | Significance |
|---|---|---|---|---|---|
| May 26, 11:35 AM | `ConnectionAcknowledged` | 203.55.81.1 | 9001 | — | TOR relay handshake initiated |
| May 26, 11:35 AM | `ConnectionSuccess` | 203.55.81.1 | 9001 | `tor.exe` | Confirmed connection to TOR relay node |
| May 26, 11:27 AM | `ConnectionSuccess` | 127.0.0.1 | 9150 | `firefox.exe` | TOR Browser SOCKS proxy active |
| May 26, 10:38 AM | `ConnectionFailed` | 127.0.0.1 | 9150 | `firefox.exe` | Initial proxy attempt (TOR not ready yet) |
| May 26, 10:38 AM | `ConnectionSuccess` | 127.0.0.1 | 9151 | `firefox.exe` | TOR Browser control port established |

![DeviceNetworkEvents results](../assets/device-network-events.png)
