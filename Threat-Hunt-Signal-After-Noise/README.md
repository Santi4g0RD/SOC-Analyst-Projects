# Threat Hunt: Signal After The Noise

![Mission Brief](assets/mission-brief.png)

## Overview

A post-intrusion threat hunt conducted inside a corporate Azure estate. The initial breach was already established — this hunt focused on reconstructing **what the operator did after gaining access**: how they persisted, how they communicated out, and what they ultimately reached for.

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
| Log Sources | DeviceLogonEvents, DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents, DeviceRegistryEvents |
| Target hosts | `azwks-phtg-01`, `azwks-phtg-02` |
| Operator account | `vmadminusername` |

---

## Hunt Walkthrough

| Phase | Finding | Link |
|---|---|---|
| P01 | Cold Trail — First Contact | [Hunt Notes](hunt-notes.md#p01--cold-trail-first-session) |
| P02 | First Footsteps — Earliest On-Host Activity | [Hunt Notes](hunt-notes.md#p02--first-footsteps-earliest-on-host-activity) |
| P03 | Quiet Roots — Persistence | [Hunt Notes](hunt-notes.md#p03--quiet-roots-persistence) |
| P04 | The Beacon Pair — C2 Callouts | [Hunt Notes](hunt-notes.md#p04--the-beacon-pair-c2-callouts) |
| P05 | Outbound Whispers — Where Traffic Went | [Hunt Notes](hunt-notes.md#p05--outbound-whispers-where-traffic-went) |
| P06 | Doors Held Open — Defence Evasion | [Hunt Notes](hunt-notes.md#p06--doors-held-open-defence-evasion) |
| P07 | Hands on the Vault — Final Actions | [Hunt Notes](hunt-notes.md#p07--hands-on-the-vault-final-actions) |
| Q01 | The Brute Force Assumption — Credential Reuse (T1078) | [Hunt Notes](hunt-notes.md#q01--the-brute-force-assumption) |
| Q02 | Lateral Movement Summary — RDP Pivot (T1021) | [Hunt Notes](hunt-notes.md#q02--lateral-movement-summary) |
| Q03 | Onward Movement Check — No Further Pivoting | [Hunt Notes](hunt-notes.md#q03--onward-movement-check) |
| Q04 | First Operator Script — PowerShell from User Profile (T1059.001) | [Hunt Notes](hunt-notes.md#q04--first-operator-script) |
| Q05 | Operator Concealment Flags — Hidden Window + Bypass (T1564.003) | [Hunt Notes](hunt-notes.md#q05--operator-concealment-flags) |
| Q06 | Staging Directory — ProgramData Masquerade (T1036) | [Hunt Notes](hunt-notes.md#q06--staging-directory) |
| Q07 | Concealment Pattern — attrib.exe Hiding (T1564) | [Hunt Notes](hunt-notes.md#q07--concealment-pattern) |
| Q08 | LOLBin Masquerade — PHtGHealthCloudSvc.exe → bitsadmin.exe (T1036.003) | [Hunt Notes](hunt-notes.md#q08--lolbin-masquerade-identification) |
| Q09 | Registry Activity Volume — 280 Events Post-Lateral | [Hunt Notes](hunt-notes.md#q09--registry-activity-volume) |
| Q10 | Persistence Signal Isolation — Run Key (T1547.001) | [Hunt Notes](hunt-notes.md#q10--persistence-signal-isolation) |
| Q11 | Run Key Value Name — PHTGHealthCloudTray (T1547.001) | [Hunt Notes](hunt-notes.md#q11--run-key-value-name) |
| Q12 | Run Key Persistence Command — Hidden PS1 at Logon (T1547.001) | [Hunt Notes](hunt-notes.md#q12--run-key-persistence-command) |
| Q13 | Second Persistence — Startup LNK (T1547.001) | [Hunt Notes](hunt-notes.md#q13--second-persistence-mechanism) |
| Q14 | Third Persistence — HKLM EventLog Registration (T1112) | [Hunt Notes](hunt-notes.md#q14--third-persistence-mechanism) |
| Q15 | Healthcheck Beacon Loop — 22 Executions (T1071.001) | [Hunt Notes](hunt-notes.md#q15--tooling-healthcheck-loop) |
| Q16 | Encoded Beacon Endpoints — Base64 Decoded C2 URIs (T1027, T1071) | [Hunt Notes](hunt-notes.md#q16--encoded-beacon-endpoints) |
| Q17 | Dual-Channel C2 Rationale — Resiliency + Function Split (T1090) | [Hunt Notes](hunt-notes.md#q17--two-beacons-why) |
| Q18 | Deployment Pattern — Download then Execute (T1105) | [Hunt Notes](hunt-notes.md#q18--deployment-pattern-recognition) |

---

## IOC Summary

| Type | Value |
|---|---|
| External IP | `173.244.55.131` |
| C2 domain | `health-cloud.cc` |
| C2 subdomain | `updates.health-cloud.cc` |
| C2 subdomain | `status.health-cloud.cc` |
| C2 IP | `104.21.36.232` (Cloudflare-fronted) |
| C2 IP | `172.67.200.204` (Cloudflare-fronted) |
| Operator account | `vmadminusername` |
| Launch host | `sarah-chen` |
| Entry host | `azwks-phtg-02` |
| Pivot host | `azwks-phtg-01` |
| Implant path | `C:\ProgramData\PHTG\HealthCloud\` |
| Implant service | `PHGTHealthCloudSvc.exe` |
| Persistence | `PHTG HealthCloud.lnk` (Startup folder) |

---

## Summary

The operator entered via `sarah-chen`'s machine (`173.244.55.131`) authenticating as `vmadminusername` to `azwks-phtg-02` at 09:27 UTC. Within 21 minutes they pivoted to `azwks-phtg-01` using a pre-staged RDP file — indicating prior reconnaissance. Persistence was established via a Startup LNK executing a hidden PowerShell script. Two Base64-encoded C2 beacons checked in to `health-cloud.cc` subdomains fronted by Cloudflare. Defender was blinded by writing its own exclusions via `msmpeng.exe`. Final actions included automated M365 authentication attempts and confirmed hands-on-keyboard access at 15:55 UTC.

**Key skills demonstrated:** KQL threat hunting across 5 MDE tables, C2 infrastructure analysis, persistence mechanism identification, defence evasion detection, MITRE ATT&CK mapping.
