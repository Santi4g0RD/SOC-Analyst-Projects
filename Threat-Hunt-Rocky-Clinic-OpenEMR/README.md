# Threat Hunt: Rocky Clinic OpenEMR Breach
## Incident Investigation Report

**Analyst:** Santiago Abel Ruiz Diaz
**Incident ID:** IR-2026-0214-EHR
**Environment:** Microsoft Sentinel / Microsoft Defender for Endpoint (`rocky83`)
**Severity:** Critical
**Status:** Confirmed compromise — full-chain breach with exfiltration
**Investigation Window:** 4–14 February 2026 UTC
**Data Sources:** `DeviceLogonEvents`, `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`, `DeviceInfo`, `AlertEvidence`

---

![Mission Brief](assets/mission-brief.png)

---

## Executive Summary

A cloud-hosted electronic health record system running OpenEMR in Docker on Azure was fully compromised over a 10-day window. **No ransomware. No service outage. No high-severity alerts fired.** The attacker operated exclusively under a legitimate admin account (`it.admin`), used commercial VPN rotation to defeat IP-based detection, and blended every action into trusted OS tooling and scheduled workflows.

The attacker established root access, read database credentials from a configuration file, installed two independent persistence mechanisms — a rogue local account and a systemd service delivering a Python reverse shell — and exfiltrated a staged archive of patient data via a Discord webhook after a direct SCP transfer was blocked at the network perimeter.

The breach was identified through proactive behavioral hunting, not alert triage. The 10-day dwell time, dual persistence, and surgical log cleanup indicate a deliberate, patient operator with familiarity with Linux host forensics and EDR evasion.

---

## Key Findings

- **Dwell time:** 10 days (2026-02-04 to 2026-02-14)
- **Initial access:** Unattributed — likely prior credential compromise via the OpenEMR web interface
- **Privilege escalation:** `sudo -i` from `it.admin` → full interactive root shell
- **Credential access:** DB credentials read from `/etc/openemr/audit_export.env`
- **Persistence 1:** Rogue `system` account created via `vipw` — bypassing `useradd` telemetry
- **Persistence 2:** Systemd service (`integration-monitor.service`) delivering Python reverse shell on every boot
- **C2:** Python3 reverse shell → `20.62.27.80:443`
- **Exfiltration:** Patient data archive posted to Discord webhook (`162.159.135.232:443`) after SCP was blocked
- **Defense evasion:** 12 selective `sed -i` deletions across `/var/log/secure` and `/var/log/messages` + timestamp forgery via `touch`
- **EDR coverage:** MDE captured all activity despite log cleanup — EDR telemetry was not affected by host-level log manipulation

---

## Hunt Methodology

**Starting point:** No alerts fired. No ransomware, no outage, no detection. The hunt was initiated on a tip that the EHR system may have been accessed outside normal business hours — not a confirmed incident, just an anomaly flag.

**Hypothesis:** If a legitimate admin account was compromised, the attacker would blend into normal operational traffic. Standard alert-based detection wouldn't surface it. The hunt had to start from behavior, not signatures.

**Phase 1 — Logon analysis as the anchor.** I started with `DeviceLogonEvents`, grouping all successful logons to `rocky83` by `RemoteIP` and `AccountName`. The goal was to surface anything that didn't fit the normal session pattern. VPN rotation appeared immediately — the same account logging in from 6+ different IP ranges, each IP used once or twice and never returning. That's not a human, that's tradecraft.

**Phase 2 — Session reconstruction.** Once the suspicious logon window was identified, I joined logon events to process events to anchor every command to a specific session. This is how the `w` command surfaced — the first thing run after login, before anything else. That's an OPSEC tell, not a normal admin behavior.

**Phase 3 — Following the operator's goals.** After confirming the session, I let the attacker's actions guide the query sequence: recon → privilege escalation → credential access → persistence → C2 → collection → exfiltration → cleanup. Each phase opened the next. The Docker inspection led to volume enumeration. Volume enumeration led to the credential file. The credential file explained why the database dump was so targeted.

**Phase 4 — Pivoting on evasion attempts.** The defense evasion phase was actually the most useful pivot point. When `sed -i` operations appeared on `/var/log/secure` and `/var/log/messages`, that confirmed the operator knew they'd been loud and was cleaning up selectively — 12 specific deletions, not a full log wipe. Selective cleanup means they knew exactly which lines to remove, which means the same lines existed in EDR telemetry.

---

## Key Analyst Observations

These findings required active reasoning — they wouldn't appear in a standard alert queue:

**1. No alerts, no outage — the hunt had to be proactive.**
MDE generated no high-severity alerts for the majority of the attack chain. The operator used a legitimate account, legitimate tools (`cat`, `curl`, `systemctl`), and legitimate services (Discord CDN). Detection required behavioral analysis across 6 log tables, not alert triage.

**2. VPN rotation as a positive signal.**
Each source IP logged in once or twice and was never reused — a pattern that defeats IP-based detection rules. Grouping by `RemoteIP` with `summarize count()` turns the evasion technique into a detection signal: legitimate admins don't rotate IPs like this.

**3. `w` as an OPSEC indicator.**
The first command run after every suspicious logon was `w` — checking who else is logged in. Normal admins don't run `w` before doing anything else. It's a red team OPSEC step that only makes sense if you're worried about being observed. Surfaced by joining logon events to process events and sorting by time.

**4. `vipw` to bypass account-creation telemetry.**
The rogue `system` account was created by writing directly to `/etc/passwd` and `/etc/shadow` using `vipw` — not `useradd` or `adduser`, which generate dedicated audit events. The account only became visible by grouping all logon successes by `AccountName` and spotting `system` with 1,092 logon events — an account that shouldn't exist on this host.

**5. `cat` instead of an editor to avoid swap files.**
The persistence service (`integration-monitor.service`) was written using `cat > /etc/systemd/system/...` rather than `vim` or `nano`. This avoids editor swap files (`.swp`, `.un~`) that would leave additional forensic artifacts. The `InitiatingProcessFileName` field in `DeviceFileEvents` exposed this — it was `cat`, not an editor.

**6. SCP blocked → Discord webhook pivot.**
Direct exfiltration via `scp` failed at the network level. The operator pivoted to posting the archive to a Discord webhook over HTTPS — legitimate traffic to `162.159.135.232:443` (Discord's Cloudflare CDN). The `DeviceNetworkEvents` `ActionType` field on the `scp` attempt showed failure; the subsequent `curl` to Discord showed success. Both events are in the same 30-minute window.

**7. Surgical log cleanup exposes the exact event window.**
Rather than wiping entire log files, the operator ran 12 targeted `sed -i` deletions against specific lines in `/var/log/secure` and `/var/log/messages`. Surgical cleanup tells you exactly what the operator considered "loud" — and those same events were already captured in EDR telemetry. The cleanup attempt confirmed the timeline rather than obscuring it.

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

## Timeline of Notable Events

| Time (UTC) | Event |
|---|---|
| 2026-02-04 | Earliest confirmed operator activity on `rocky83` |
| 2026-02-06 | `docker inspect openemr-mariadb` — container interrogation (first instance) |
| 2026-02-07 01:11 | `cat /etc/openemr/audit_export.env` — DB credentials read as root |
| 2026-02-08 16:25 | First confirmed suspicious SSH logon from `37.19.221.234` (Amsterdam, NL) |
| 2026-02-09 | `docker inspect` repeated — second container interrogation |
| 2026-02-10 18:10 | `/opt/backup/scripts/backup_manifest.sh` modified — staging logic injected |
| 2026-02-10 22:00 | `integration_state_2026-02-10_22-00-01.tar.gz` created at `/var/lib/integrations` |
| 2026-02-11 04:16 | `systemd` fires `integration-monitor.service` — Python reverse shell to `20.62.27.80:443` |
| 2026-02-11 04:18 | `/bin/sh -i` PID 8000 — interactive operator session via C2 |
| 2026-02-11 ~04:30 | `scp` exfiltration attempt — blocked at network perimeter |
| 2026-02-11 16:13 | 12 selective `sed -i` deletions across `/var/log/secure` and `/var/log/messages` |
| 2026-02-11 16:16 | `touch` backdates `/var/log/messages` to 2026-02-06 12:00:00 — EDR alert fires |
| 2026-02-13 ~20:00 | `curl` POST to Discord webhook — patient data archive exfiltrated |
| 2026-02-14 | Investigation window closes |

---

## Impact Assessment

| Category | Finding |
|---|---|
| Confirmed compromise | Yes |
| Dwell time | 10 days |
| Root access obtained | Yes — via `sudo -i` from `it.admin` |
| Credentials compromised | Yes — DB credentials from `/etc/openemr/audit_export.env` |
| Patient data exfiltrated | Yes — MariaDB archive (`integration_state_2026-02-10_22-00-01.tar.gz`) posted to Discord |
| Persistence established | Yes — two independent mechanisms (rogue account + systemd service) |
| C2 active | Yes — Python reverse shell to `20.62.27.80:443` |
| Log tampering | Yes — 12 selective deletions + timestamp forgery (ineffective against EDR) |
| Service disruption | None — breach operated entirely under legitimate tooling |
| Regulatory exposure | Likely — patient health records in scope (HIPAA applicability) |

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

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Detail |
|---|---|---|---|
| Initial Access | External Remote Services | T1133 | SSH access as `it.admin` from VPN-rotating IPs |
| Discovery | System Information Discovery | T1082 | One-shot OS fingerprint via concatenated release files |
| Discovery | File and Directory Discovery | T1083 | Recursive Docker volume enumeration via `find` |
| Privilege Escalation | Abuse Elevation Control Mechanism: Sudo | T1548.003 | `sudo -i` → full interactive root shell |
| Credential Access | Unsecured Credentials: Credentials in Files | T1552.001 | DB credentials read from `/etc/openemr/audit_export.env` |
| Persistence | Create Account: Local Account | T1136.001 | Rogue `system` account via `vipw` — bypassed `useradd` telemetry |
| Persistence | Create or Modify System Process: Systemd Service | T1543.002 | `integration-monitor.service` delivers Python reverse shell on boot |
| Command & Control | Non-Standard Port | T1571 | Python reverse shell to `20.62.27.80:443` |
| Command & Control | Command and Scripting Interpreter: Python | T1059.006 | Python3 reverse shell spawned by systemd |
| Collection | Local Data Staging | T1074.001 | Archive staged at `/var/lib/integrations` via hijacked backup script |
| Collection | Archive Collected Data | T1560.001 | Patient data compressed as `.tar.gz` |
| Exfiltration | Exfiltration Over Web Service | T1567 | `curl` POST to Discord webhook (Cloudflare CDN) |
| Exfiltration | Exfiltration Over Alternative Protocol | T1048 | SCP attempted and blocked; Discord HTTPS succeeded |
| Defense Evasion | Indicator Removal: Clear Linux Logs | T1070.003 | 12 selective `sed -i` deletions from `/var/log/secure` and `/var/log/messages` |
| Defense Evasion | Indicator Removal: Timestomp | T1070.006 | `touch` used to backdate `/var/log/messages` to 2026-02-06 |

---

## Containment & Remediation

### Immediate Containment
1. **Isolate the host** — remove `rocky83` from the network pending full forensic review
2. **Disable `it.admin`** and revoke all active sessions and SSH keys
3. **Remove the rogue `system` account** — delete entries from `/etc/passwd` and `/etc/shadow`; verify no cron jobs or processes run as `system`
4. **Disable and delete `integration-monitor.service`** — `systemctl disable integration-monitor && systemctl stop integration-monitor && rm /etc/systemd/system/integration-monitor.service`
5. **Block C2 IP** `20.62.27.80` at the network perimeter
6. **Rotate all credentials** in `/etc/openemr/audit_export.env` — DB password, API keys, any service accounts
7. **Restore `/var/log/secure` and `/var/log/messages`** from backup or reconstruct from EDR telemetry

### Near-Term Hardening
1. **Rotate all MariaDB and OpenEMR application credentials** — assume full DB access was achieved
2. **Audit `/etc/systemd/system/`** for additional rogue service units beyond `integration-monitor.service`
3. **Audit `/opt/backup/scripts/`** and all scheduled tasks/crons for further modifications
4. **Review all local accounts** on the host — run `getent passwd` and cross-reference against the expected user baseline
5. **Restrict `sudo` configuration** — `sudo -i` grants a full root shell; scope sudo rules to specific commands only
6. **Move credentials to a secrets manager** (e.g., Azure Key Vault) — flat `.env` files accessible as root are a single `cat` away from full credential access
7. **Tighten egress firewall rules** — SCP to unknown IPs was blocked; extend controls to HTTPS POST from EHR hosts to consumer SaaS endpoints (Discord, Slack, etc.)

### Strategic Improvements
1. **Alert on `vipw` execution** — direct writes to `/etc/passwd` and `/etc/shadow` are never a normal admin operation; this should be a high-fidelity alert
2. **Alert on new files under `/etc/systemd/system/`** — creation of service unit files outside a known change window should trigger review
3. **Alert on `curl` POST from server-class hosts to SaaS CDNs** — `curl -X POST` from an EHR server to `discord.com` or `discordapp.com` is not expected traffic
4. **Implement file integrity monitoring (FIM)** on `/etc/passwd`, `/etc/shadow`, `/etc/systemd/system/`, and application credential files
5. **Restrict SSH access** — implement IP allowlisting or require VPN/bastion for SSH to healthcare data systems; eliminate direct internet-facing SSH
6. **Alert on impossible travel and IP rotation** — the same account logging in from 6 different IP ranges in a 10-day window is detectable with a simple `summarize count() by RemoteIP` grouped by account

---

## Full Hunt Notes

For the complete question-by-question KQL walkthrough and per-finding analysis, see [hunt-notes.md](hunt-notes.md).

**Key skills demonstrated:** Proactive behavioral threat hunting across 6 MDE/Sentinel tables, Linux host forensics, Docker container attack surface analysis, persistence mechanism identification (account + systemd), C2 and exfiltration path reconstruction, MITRE ATT&CK mapping, IR lifecycle (detect → analyze → contain → remediate).
