# Threat Hunt: Rocky Clinic OpenEMR Breach

![Mission Brief](assets/mission-brief.png)

## Overview

A full-chain compromise of a cloud-hosted electronic health record system running OpenEMR in Docker on Azure. **No ransomware, no alerts, no outage.** The attacker operated entirely under a legitimate admin account, blended persistence into trusted OS tooling, and exfiltrated patient data through a Discord webhook after direct transfer was blocked by network controls.

**Environment:** Microsoft Sentinel / Microsoft Defender for Endpoint (MDE)  
**Investigation Window:** 4–14 February 2026 UTC  
**Platform:** Azure — Rocky Linux VM → Docker (docker-compose) → OpenEMR + MariaDB  
**Analyst:** Abel

---

## Environment

| Component | Details |
|---|---|
| SIEM | Microsoft Sentinel |
| EDR | Microsoft Defender for Endpoint (MDE) |
| Log Sources | DeviceFileEvents, DeviceProcessEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceInfo, AlertEvidence |
| Target Host | `rocky83.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net` |
| Application Stack | Azure VM → Docker (docker-compose) → OpenEMR + MariaDB |
| Operator Account | `it.admin` |

---

## Attack Chain

### Initial Access — Unattributed; SSH Sessions Begin 2026-02-08

The initial access vector was not attributed during this investigation. Earliest confirmed operator activity appears on **2/6** — predating the suspicious SSH sessions — suggesting the foothold was either established before the investigation window or through the OpenEMR web interface.

SSH sessions were conducted as `it.admin` from a VPN-rotating pool of IPs. The first confirmed suspicious external logon came from `37.19.221.234` on **2026-02-08 at 16:25 UTC**, with subsequent sessions rotating across `37.19.x`, `149.40.x`, `185.236.x`, `149.22.x`, and `146.70.202.x` ranges throughout the window. Each IP logged in once or twice and never returned — consistent with commercial VPN rotation to defeat IP-based detection.

The operator's first action after logon: `w` — checking who else is logged in before doing anything loud. A standard OPSEC step.

```kql
// Identify suspicious external logons — group by RemoteIP to surface VPN rotation
DeviceLogonEvents
| where TimeGenerated between (datetime(2026-02-04T00:00:00) .. datetime(2026-02-14T00:00:00))
| where DeviceName has "rocky83"
| where AccountName == "it.admin"
| where LogonType == "Network"
| summarize LogonCount = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by RemoteIP, AccountName, LogonType, DeviceName
| order by LogonCount desc
```

![Q03 — Logon Analysis](assets/q03-logon-analysis.png)

```kql
// Anchor the suspicious session and find the first w command (who-is-logged-in recon)
let logons = DeviceLogonEvents
| where TimeGenerated between (datetime(2026-02-04T00:00:00) .. datetime(2026-02-14T18:00:00))
| where AccountName == "it.admin"
| where LogonType == "Network"
| where RemoteIP != ""
| project LogonTime = TimeGenerated, RemoteIP, DeviceName, AccountName;
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-02-04T15:00:00) .. datetime(2026-02-14T17:00:00))
| where AccountName == "it.admin"
| where ProcessCommandLine has_any ("w", "who", "last", "-bash")
| join kind=leftouter (logons) on DeviceName, AccountName
| where LogonTime <= TimeGenerated
| summarize arg_max(LogonTime, RemoteIP, LogonTime) by TimeGenerated, ProcessId, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessCommandLine
| project TimeGenerated, ProcessId, DeviceName, AccountName, ProcessCommandLine, RemoteIP, LogonTime
| order by TimeGenerated asc
```

![Q03 — w Command](assets/q03-w-command.png)

---

### Reconnaissance — OS Fingerprint + Docker Stack Interrogation

The operator moved efficiently through host enumeration. OS fingerprint was done in a single command:

```bash
cat /etc/os-release /etc/redhat-release /etc/rocky-release /etc/system-release
```

Four files, one shot. The EDR recorded it as one process event. The host came back as **RockyLinux** — confirmed in `DeviceInfo.OSDistribution`.

```kql
// Catch the one-shot OS fingerprint command
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-02-04T00:00:00) .. datetime(2026-02-14T00:00:00))
| where DeviceName has "rocky83"
| where ProcessCommandLine has "/etc/" and ProcessCommandLine has "release"
| project TimeGenerated, ProcessId, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

![Q06 — Release Files](assets/q06-release-files.png)

Docker stack interrogation followed — `docker inspect openemr-mariadb` run twice (2/6 and 2/9), pulling the container's full configuration, network bindings, and environment variables.

```kql
// Detect container interrogation
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-02-04T00:00:00) .. datetime(2026-02-14T23:59:00))
| where AccountName == "root"
| where ProcessCommandLine has "docker inspect"
| project TimeGenerated, ProcessId, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

![Q09 — Docker Inspect](assets/q09-docker-inspect.png)

Followed by a recursive enumeration of all Docker volume storage and a targeted `ls` to physically map the MariaDB data path.

```kql
// Find the recursive volume enumeration
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName has "rocky83"
| where FileName == "find"
| where ProcessCommandLine has "docker"
| project TimeGenerated, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

![Q11 — Find Volumes](assets/q11-find-volumes.png)

```kql
// Identify the exact database volume path
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName has "rocky83"
| where ProcessCommandLine has "/var/lib/docker/volumes/r0ckyyy335_mariadb"
| project TimeGenerated, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

![Q12 — DB Path](assets/q12-db-path.png)

**MITRE:** T1082 — System Information Discovery, T1083 — File and Directory Discovery

---

### Privilege Escalation — sudo -i

From the `it.admin` shell, a single command dropped the operator into a fully interactive root shell — not a scoped `sudo <command>`, a full root shell. All subsequent activity ran as root.

```kql
// Trace the full operator session anchored to the suspicious logon
let suspiciousSession = DeviceLogonEvents
| where TimeGenerated between (datetime(2026-02-08T16:00:00) .. datetime(2026-02-08T17:00:00))
| where DeviceName has "rocky83"
| where AccountName == "it.admin"
| where RemoteIP == "37.19.221.234"
| project LogonTime = TimeGenerated, DeviceName, AccountName;
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-02-04T00:00:00) .. datetime(2026-02-14T00:00:00))
| where DeviceName has "rocky83"
| where AccountName == "it.admin"
| where InitiatingProcessCommandLine == "-bash"
| join kind=inner (suspiciousSession) on DeviceName, AccountName
| where TimeGenerated >= LogonTime
| project TimeGenerated, ProcessId, FileName, ProcessCommandLine, SHA256
| order by TimeGenerated asc
```

![Q08 — Sudo Escalation](assets/q08-sudo-escalation.png)

**MITRE:** T1548.003 — Sudo and Sudo Caching

---

### Credential Access — Automation Config File

As root, the operator read a privileged configuration file outside the application directory — `audit_export.env` holds DB credentials valid across reboots. A follow-up `grep` at 01:13 UTC confirmed the password field was present.

```bash
cat /etc/openemr/audit_export.env   # 2026-02-07 01:11:54 UTC
grep -q ^DB_PASS= /etc/openemr/audit_export.env   # 01:13:11 UTC
```

```kql
// Surface root-context file reads in the narrow window around the credential access
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-02-07T01:09:00) .. datetime(2026-02-07T01:15:00))
| where DeviceName has "rocky83"
| where AccountName == "root"
| project TimeGenerated, ProcessCommandLine, FolderPath, InitiatingProcessCommandLine, FileName
| order by TimeGenerated asc
```

![Q10 — Root Commands](assets/q10-root-commands.png)
![Q10 — Cat Env File](assets/q10-cat-env-file.png)

**MITRE:** T1552.001 — Credentials in Files

---

### Persistence — Two Independent Mechanisms

**1. Rogue local account — `system`**

Rather than `useradd` or `adduser` — which generate dedicated audit events — the operator wrote directly to `/etc/passwd` and `/etc/shadow` using `vipw`. On Rocky Linux, `system` is not a real local account. Grouping all logon successes by account name surfaces it with 1,092 logon events — the anomaly.

```kql
// Group all logon successes — the odd account stands out immediately
DeviceLogonEvents
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName has "rocky83"
| where ActionType == "LogonSuccess"
| summarize LogonCount = count() by AccountName
| order by LogonCount asc
```

![Q15 — System Account](assets/q15-system-account.png)

```kql
// Confirm vipw was used to bypass standard account-creation telemetry
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName has "rocky83"
| where ProcessCommandLine has "vipw"
| project TimeGenerated, SHA256, FileName, FolderPath, ProcessCommandLine
```

![Q16 — vipw](assets/q16-vipw.png)

**MITRE:** T1136.001 — Create Account: Local Account

**2. Systemd service — `integration-monitor.service`**

A service unit file was written under `/etc/systemd/system/` using `cat` — not `vim` or `nano` — to avoid editor swap-file artifacts. The service delivers the C2 payload on every boot without any interactive logon.

```kql
// Detect new or modified unit files — InitiatingProcessFileName reveals cat, not an editor
DeviceFileEvents
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName has "rocky83"
| where FolderPath has "/etc/systemd/system"
| where ActionType in ("FileCreated", "FileModified")
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

![Q17 — Service Created](assets/q17-service-created.png)
![Q18 — Cat Creation](assets/q18-cat-creation.png)

```kql
// Track all SHA256 versions of the service file to identify which was active at C2 launch
DeviceFileEvents
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName has "rocky83"
| where FileName == "integration-monitor.service"
| project TimeGenerated, SHA256, ActionType, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

![Q19 — Service SHA256](assets/q19-service-sha256.png)

**MITRE:** T1543.002 — Create or Modify System Process: Systemd Service

---

### Command & Control — Python Reverse Shell via Systemd

On **2026-02-11 at 04:16 UTC**, `systemd` fired `integration-monitor.service`, spawning a Python3 reverse shell to `20.62.27.80:443`. Two minutes later, `/bin/sh -i` (PID **8000**) became the interactive operator session.

```kql
// Find the reverse shell spawned by systemd
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-02-11T04:16:00) .. datetime(2026-02-11T05:00:00))
| where DeviceName has "rocky83"
| where InitiatingProcessFileName == "systemd"
| where ProcessCommandLine has_any ("python", "bash", "nc", "sh", "curl", "wget")
| project TimeGenerated, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

![Q20 — Reverse Shell](assets/q20-reverse-shell.png)

```kql
// Identify the interactive /bin/sh -i subprocess (the actual operator session)
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-02-11T04:16:00) .. datetime(2026-02-11T05:00:00))
| where DeviceName has "rocky83"
| where AccountName == "it.admin"
| where ProcessCommandLine has "-i"
| where FileName in ("sh", "bash", "dash")
| project TimeGenerated, ProcessId, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

![Q21 — Shell PID](assets/q21-shell-pid.png)

**MITRE:** T1059.006 — Command and Scripting Interpreter: Python, T1543.002 — Systemd Service

---

### Collection & Staging

`/opt/backup/scripts/backup_manifest.sh` — a script that runs automatically as `svc.backup` — was modified twice on **2026-02-10 at 18:10–18:11 UTC**. The operator injected staging logic into an already-trusted, already-scheduled workflow. Data was archived as `integration_state_2026-02-10_22-00-01.tar.gz` at `/var/lib/integrations`.

```kql
// Detect modifications to scripts in trusted operational paths
DeviceFileEvents
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName has "rocky83"
| where FolderPath has_any ("/opt/", "/usr/local/")
| where ActionType in ("FileModified", "FileCreated", "FileRenamed")
| project TimeGenerated, ActionType, FileName, FolderPath
| order by TimeGenerated asc
```

![Q13 — Backup Script](assets/q13-backup-script.png)

```kql
// Find archive creation commands pointing to the staging directory
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName has "rocky83"
| where AccountName has_any ("it.admin", "root")
| where FileName in ("tar", "gzip", "zip", "cp", "rsync")
| project TimeGenerated, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

![Q14 — Staging Dir](assets/q14-staging-dir.png)

```kql
// Confirm the staged archive filename via transfer tool command lines
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-02-11T04:00:00) .. datetime(2026-02-11T06:00:00))
| where DeviceName has "rocky83"
| where ProcessCommandLine has_any ("scp", "sftp", "rsync", "curl", "wget", "nc")
| where AccountName == "it.admin"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

![Q22 — Staged Archive](assets/q22-staged-archive.png)

**MITRE:** T1053 — Scheduled Task/Job, T1074.001 — Local Data Staging, T1560.001 — Archive Collected Data

---

### Exfiltration — Pivot to Discord After SCP Blocked

Direct SCP to the C2 host was blocked by network controls. The operator pivoted to `curl` posting the archive to a Discord webhook — legitimate HTTPS traffic resolving to `162.159.135.232:443` (Discord's Cloudflare CDN).

```kql
// Find the scp attempt and confirm it failed
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-02-11T04:00:00) .. datetime(2026-02-11T06:00:00))
| where DeviceName has "rocky83"
| where FileName == "scp"
| where AccountName == "it.admin"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

![Q23 — SCP Command](assets/q23-scp-command.png)

```kql
// Confirm the network-level failure on the scp attempt
DeviceNetworkEvents
| where TimeGenerated between (datetime(2026-02-11T04:00:00) .. datetime(2026-02-11T06:00:00))
| where DeviceName has "rocky83"
| where InitiatingProcessFileName == "scp"
| project TimeGenerated, ActionType, RemoteIP, RemotePort, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

![Q23 — SCP Failed](assets/q23-scp-failed.png)

```kql
// Find the successful curl exfiltration to Discord
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-02-11T04:20:00) .. datetime(2026-02-14T00:00:00))
| where DeviceName has "rocky83"
| where FileName == "curl"
| where ProcessCommandLine !has "127.0.0.1"
| where ProcessCommandLine !has "localhost"
| project TimeGenerated, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

![Q24 — Curl Discord](assets/q24-curl-discord.png)

```kql
// Resolve the actual exfiltration IP and port from the network event
DeviceNetworkEvents
| where TimeGenerated between (datetime(2026-02-13T20:00:00) .. datetime(2026-02-13T21:00:00))
| where DeviceName has "rocky83"
| where InitiatingProcessFileName == "curl"
| project TimeGenerated, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

![Q25 — Exfil Endpoint](assets/q25-exfil-endpoint.png)

**MITRE:** T1567 — Exfiltration Over Web Service (SaaS abuse), T1048 — Exfiltration Over Alternative Protocol

---

### Defense Evasion — Surgical Log Cleanup + Timestamp Forgery

Between **16:13–16:16 UTC on 2026-02-11**, the operator ran **12 selective `sed -i` delete operations** across `/var/log/secure` and `/var/log/messages`. `/var/log/messages` was then backdated to **2026-02-06 12:00:00** via `touch`. The EDR caught it anyway.

```kql
// Count the selective sed deletions across both log files
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-02-11T16:13:00) .. datetime(2026-02-11T16:16:00))
| where DeviceName has "rocky83"
| where FileName == "sed"
| where ProcessCommandLine has_any ("/var/log/secure", "/var/log/messages")
| project TimeGenerated, AccountName, ProcessCommandLine
| order by TimeGenerated asc
```

![Q26 — Sed Operations](assets/q26-sed-operations.png)

```kql
// Find the touch command used to backdate /var/log/messages
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName has "rocky83"
| where ProcessCommandLine has "/var/log/messages"
| where FileName in ("touch", "timestomp")
| project TimeGenerated, AccountName, ProcessCommandLine
| order by TimeGenerated asc
```

![Q28 — Timestamp Forge](assets/q28-timestamp-forge.png)

```kql
// Confirm the EDR alert raised on the timestomp activity
AlertEvidence
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName has "rocky83"
| where Title has "timestamp"
| project TimeGenerated, Title, AttackTechniques, AlertId
```

![Q29 — Alert Classification](assets/q29-alert-classification.png)

**MITRE:** T1070.003 — Clear Linux or Mac System Logs, T1070.006 — Timestomp

---

## IOC Summary

| Type | Value |
|---|---|
| Target host | `rocky83.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net` |
| Operator account | `it.admin` |
| Initial suspicious IP | `37.19.221.234` (VPN — first session, 2026-02-08) |
| VPN rotation cluster | `37.19.x`, `149.40.x`, `185.236.x`, `149.22.x`, `159.26.x`, `146.70.202.x` |
| C2 IP | `20.62.27.80:443` |
| Exfil endpoint | `162.159.135.232:443` (Discord CDN) |
| Staged archive | `integration_state_2026-02-10_22-00-01.tar.gz` |
| Staging path | `/var/lib/integrations` |
| Credential artifact | `/etc/openemr/audit_export.env` |
| Rogue account | `system` (created via `vipw`) |
| Persistence service | `integration-monitor.service` |
| Hijacked script | `/opt/backup/scripts/backup_manifest.sh` |

---

## Full Hunt Notes

For the complete question-by-question KQL walkthrough and per-finding analysis, see [hunt-notes.md](hunt-notes.md).

**Key skills demonstrated:** KQL threat hunting across 6 MDE/Sentinel tables, Linux host forensics, Docker container attack surface analysis, persistence mechanism identification (account + systemd), C2 and exfiltration path reconstruction, MITRE ATT&CK mapping.
