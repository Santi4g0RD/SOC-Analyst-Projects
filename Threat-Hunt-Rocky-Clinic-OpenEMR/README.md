# Threat Hunt: Rocky Clinic OpenEMR Breach

![Mission Brief](assets/mission-brief.png)

## Overview

A post-intrusion threat hunt reconstructing a full-chain compromise of a cloud-hosted electronic health record system. **No ransomware, no alerts, no outage.** The attacker operated quietly — methodical reconnaissance, privilege escalation through trusted tooling, persistent access via a fake OS account and a systemd service, and data exfiltrated through a Discord webhook after `scp` was blocked.

**Environment:** Microsoft Sentinel / Microsoft Defender for Endpoint (MDE)  
**Investigation Window:** 4–14 February 2026 UTC  
**Platform:** Azure — Rocky Linux VM hosting OpenEMR in Docker  
**Analyst:** Abel

---

## Environment

| Component | Details |
|---|---|
| SIEM | Microsoft Sentinel |
| EDR | Microsoft Defender for Endpoint (MDE) |
| Log Sources | DeviceFileEvents, DeviceProcessEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceInfo, AlertEvidence |
| Target Host | `rocky83.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net` |
| Application Stack | Azure VM → Docker (docker-compose) → OpenEMR container + MariaDB |
| Operator Account | `it.admin` |

---

## Hunt Walkthrough

| Phase | Finding | Link |
|---|---|---|
| Q01 | Asset Anchor — FQDN of the OpenEMR host | [Hunt Notes](hunt-notes.md#q01--asset-anchor) |
| Q02 | Hosting Model — Docker confirmed as container runtime | [Hunt Notes](hunt-notes.md#q02--hosting-model) |
| Q03 | First Behavioural Tell — `w` run to check logged-in users (PID 17507) | [Hunt Notes](hunt-notes.md#q03--first-behavioural-tell) |
| Q04 | Session Boundary Fingerprint — SHA256 of last operator binary before cleanup | [Hunt Notes](hunt-notes.md#q04--session-boundary-fingerprint) |
| Q05 | Account Attribution — `it.admin` behind all suspicious remote sessions | [Hunt Notes](hunt-notes.md#q05--account-attribution) |
| Q06 | Environment Confirmation — 4 `/etc` release files read in one fingerprinting command | [Hunt Notes](hunt-notes.md#q06--environment-confirmation) |
| Q07 | Platform Reality Check — `RockyLinux` as recorded by EDR | [Hunt Notes](hunt-notes.md#q07--platform-reality-check) |
| Q08 | Crossing the Trust Line — `sudo -i` escalates to root shell | [Hunt Notes](hunt-notes.md#q08--crossing-the-trust-line) |
| Q09 | Runtime Layer Interrogation — `docker inspect openemr-mariadb` (T1082) | [Hunt Notes](hunt-notes.md#q09--runtime-layer-interrogation) |
| Q10 | The Single File That Explains Everything — `cat /etc/openemr/audit_export.env` (T1552) | [Hunt Notes](hunt-notes.md#q10--the-single-file-that-explains-everything) |
| Q11 | Physical Mapping Confirmation — recursive `find` of Docker volume storage (T1083) | [Hunt Notes](hunt-notes.md#q11--physical-mapping-confirmation) |
| Q12 | Where the Data Actually Lives — `/var/lib/docker/volumes/r0ckyyy335_mariadb_data/_data` | [Hunt Notes](hunt-notes.md#q12--where-the-data-actually-lives) |
| Q13 | Hijacking a Trusted Repeating Path — `backup_manifest.sh` modified for staging (T1053) | [Hunt Notes](hunt-notes.md#q13--hijacking-a-trusted-repeating-path) |
| Q14 | Staging Where Nobody Looks First — `/var/lib/integrations` (T1074) | [Hunt Notes](hunt-notes.md#q14--staging-where-nobody-looks-first) |
| Q15 | Quiet Persistence Obfuscation — rogue `system` account (T1078) | [Hunt Notes](hunt-notes.md#q15--quiet-persistence-obfuscation) |
| Q16 | Identity Creation Without Footprints — `vipw` used to avoid standard account tools (T1136) | [Hunt Notes](hunt-notes.md#q16--identity-creation-without-footprints) |
| Q17 | Secondary Non-Interactive Persistence — `integration-monitor.service` (T1543.002) | [Hunt Notes](hunt-notes.md#q17--secondary-non-interactive-persistence) |
| Q18 | No Editor File Creation — service unit written with `cat` to avoid editor telemetry | [Hunt Notes](hunt-notes.md#q18--no-editor-file-creation) |
| Q19 | Pre-Activation Integrity Check — SHA256 of service file version used to launch C2 | [Hunt Notes](hunt-notes.md#q19--pre-activation-integrity-check) |
| Q20 | Outbound Control Command — Python3 reverse shell to `20.62.27.80:443` (T1059.006) | [Hunt Notes](hunt-notes.md#q20--outbound-control-command) |
| Q21 | Reverse Shell Process ID — interactive `/bin/sh -i` subprocess (PID 8000) | [Hunt Notes](hunt-notes.md#q21--reverse-shell-process-identification) |
| Q22 | Staged Archive — `integration_state_2026-02-10_22-00-01.tar.gz` (T1560) | [Hunt Notes](hunt-notes.md#q22--staged-archive-identification) |
| Q23 | First Exfiltration Attempt — `scp` to `20.62.27.80` blocked by network controls | [Hunt Notes](hunt-notes.md#q23--first-exfiltration-attempt) |
| Q24 | Successful Exfiltration Pivot — `curl` to Discord webhook bypasses controls (T1567) | [Hunt Notes](hunt-notes.md#q24--successful-exfiltration-pivot) |
| Q25 | Exfil Endpoint — `162.159.135.232:443` (Discord infrastructure) | [Hunt Notes](hunt-notes.md#q25--exfil-endpoint) |
| Q26 | Selective Log Erasure — 12 `sed -i` delete operations across two log files (T1070.003) | [Hunt Notes](hunt-notes.md#q26--selective-log-erasure) |
| Q27 | Log Manipulation Primitive — `sed` for in-place text deletion | [Hunt Notes](hunt-notes.md#q27--log-manipulation-primitive) |
| Q28 | Timeline Distortion — `/var/log/messages` backdated to `2026-02-06 12:00:00` (T1070.006) | [Hunt Notes](hunt-notes.md#q28--timeline-distortion) |
| Q29 | Cleanup Alert Classification — EDR raised `Indicator Removal (T1070)` + `Timestomp (T1070.006)` | [Hunt Notes](hunt-notes.md#q29--cleanup-alert-classification) |

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
| Exfil method | `curl` POST to Discord webhook |
| Staged archive | `integration_state_2026-02-10_22-00-01.tar.gz` |
| Staging path | `/var/lib/integrations` |
| Credential artifact | `/etc/openemr/audit_export.env` |
| Rogue account | `system` (created via `vipw`) |
| Persistence service | `integration-monitor.service` |
| Hijacked script | `/opt/backup/scripts/backup_manifest.sh` |

---

## Summary

The operator entered via SSH as `it.admin` from a VPN-rotating IP (`37.19.221.234`) on 2026-02-08. Within the same session they ran `w` to check for other active users, fingerprinted the OS with a single `cat` across four `/etc` release files, then escalated to root via `sudo -i`. They interrogated the Docker stack with `docker inspect`, physically mapped the database volume with a recursive `find`, and extracted DB credentials from `/etc/openemr/audit_export.env`. A rogue `system` account was created using `vipw` to avoid standard account-management tooling. A systemd service (`integration-monitor.service`) was written with `cat` — no editor telemetry — and used to deliver a Python reverse shell to `20.62.27.80:443`. Data was archived at `/var/lib/integrations`, and an initial `scp` exfil attempt to the C2 host was blocked by network controls; the operator pivoted to `curl` posting the archive to a Discord webhook, which resolved to `162.159.135.232:443`. Cleanup consisted of 12 selective `sed -i` deletions across `/var/log/secure` and `/var/log/messages`, followed by `touch` to backdate `/var/log/messages` to 2026-02-06 — caught by the EDR as `Timestomp (T1070.006)`.

**Key skills demonstrated:** KQL threat hunting across 6 MDE/Sentinel tables, Linux host forensics, Docker container attack surface analysis, persistence mechanism identification (account + systemd), C2 and exfiltration path reconstruction, MITRE ATT&CK mapping (T1059, T1070, T1074, T1078, T1083, T1136, T1543, T1552, T1560, T1567).
