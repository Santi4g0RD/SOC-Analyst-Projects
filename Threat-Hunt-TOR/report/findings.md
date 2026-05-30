# Findings Report

**Hunt Title:** Detection of Unauthorized TOR Browser Installation and Use  
**Device:** `abel-win11-vm`  
**Date of Activity:** May 26, 2026  
**Analyst:** Abel  

---

## Scenario

Management suspects employees may be using TOR browsers to bypass network security controls.
Recent network logs show unusual encrypted traffic patterns and connections to known TOR entry
nodes. Anonymous reports also suggest employees discussing ways to access restricted sites during
work hours. Goal: detect TOR usage and notify management if confirmed.

---

## Timeline of Events

| Time | Event |
|---|---|
| 10:38 AM | TOR Browser portable installer executed on `abel-win11-vm` |
| 10:38 AM | `firefox.exe` launched from `C:\Users\lababel\Desktop\` |
| 10:38 AM | Initial SOCKS proxy connection to `127.0.0.1:9150` failed (TOR not ready) |
| 10:38 AM | TOR control port `127.0.0.1:9151` successfully established |
| ~10:38–1:29 PM | Multiple TOR-related files created on Desktop |
| 11:27 AM | `firefox.exe` successfully connected to SOCKS proxy `127.0.0.1:9150` |
| 11:35 AM | `tor.exe` established `ConnectionSuccess` to external relay `203.55.81.1:9001` |

---

## Key Findings

### 1. TOR Browser Was Installed
`DeviceFileEvents` shows `Tor Browser.lnk`, launcher components (`Tor Launcher.txt`,
`Torbutton.txt`), and related files (`torbat`, `icebuttom.bat`) created on the Desktop —
confirming installation.

### 2. TOR Browser Was Executed
`DeviceProcessEvents` confirms `firefox.exe` (TOR Browser's engine) was launched from
`C:\Users\lababel\Desktop\` — outside standard Program Files. The `portable` flag in the command
line indicates intentional evasion of registry/install-log traces.

### 3. A Full TOR Circuit Was Established
`DeviceNetworkEvents` shows `tor.exe` successfully connected to external relay `203.55.81.1` on
port `9001`, confirming live traffic reached the TOR network — not just local activity.

### 4. Suspicious File: `tor-shopping-list.txt`
A file named `tor-shopping-list.txt` was created on the Desktop during the session. The filename
strongly implies the user was planning or conducting dark web transactions. The file was
subsequently deleted, indicating awareness of forensic artifacts.

### 5. Activity Was Deliberate
- Portable installation chosen to avoid standard install paths and registry entries
- All activity concentrated in a single focused session (10:38 AM – 11:35 AM)
- File deletion of `tor-shopping-list.txt` shows intent to cover tracks

---

## Conclusions

The evidence across all three MDE tables (`DeviceFileEvents`, `DeviceProcessEvents`,
`DeviceNetworkEvents`) is fully corroborated and confirms:

1. TOR Browser was **intentionally installed** in portable mode on `abel-win11-vm`
2. TOR Browser was **executed** and a full TOR circuit was **successfully established**
3. The user **accessed the TOR network** and created a suspicious file suggesting dark web activity
4. The user attempted to **cover their tracks** by deleting the file and using portable mode

**Recommended Action:** Notify management. Escalate for HR/legal review. Isolate device for
further forensic investigation. Block TOR-related ports (9001, 9030, 9040, 9050, 9051, 9150,
9151) at the network perimeter.

---

## MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|---|---|---|
| Proxy: Multi-hop Proxy | T1090.003 | `tor.exe` connected to external relay on port 9001 |
| User Execution | T1204 | User manually ran portable TOR installer |
| Masquerading | T1036 | Portable install used to avoid standard program paths |
