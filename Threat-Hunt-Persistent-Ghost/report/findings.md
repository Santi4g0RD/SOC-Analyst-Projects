# Threat Hunt Findings Report

## Executive Summary

> _Fill in after running the simulation. Summarize what was detected, the attack timeline, and the impact._

**Hunt Name:** Operation Persistent Ghost  
**Date:** <!-- add date -->  
**Analyst:** Santi4g0RD  
**Environment:** Azure Windows 11 VM + Microsoft Sentinel  

---

## Hypothesis

> An attacker who gained initial access to a Windows endpoint would attempt to establish
> persistence via scheduled tasks and registry run keys, using PowerShell as the execution mechanism.

---

## Techniques Hunted

| MITRE ID | Technique | Detected | Evidence |
|---|---|---|---|
| T1059.001 | PowerShell Execution | <!-- Yes/No --> | <!-- Event ID, screenshot --> |
| T1027 | Obfuscated Command | <!-- Yes/No --> | <!-- Event ID, screenshot --> |
| T1053.005 | Scheduled Task Persistence | <!-- Yes/No --> | <!-- Event ID, screenshot --> |
| T1547.001 | Registry Run Key Persistence | <!-- Yes/No --> | <!-- Event ID, screenshot --> |

---

## Attack Timeline

| Time | Event | Technique | Source |
|---|---|---|---|
| <!-- HH:MM --> | PowerShell launched | T1059.001 | Event ID 4688 |
| <!-- HH:MM --> | Encoded command executed | T1027 | Event ID 4688 |
| <!-- HH:MM --> | Scheduled task created | T1053.005 | Event ID 4698 |
| <!-- HH:MM --> | Registry Run key written | T1547.001 | Sysmon Event ID 13 |

---

## Findings

### Finding 1 — PowerShell Execution
- **Event ID:** 4688
- **Command Line:** `<!-- paste from query results -->`
- **Process:** `powershell.exe`
- **Parent Process:** `<!-- fill in -->`
- **Screenshot:** <!-- add link or embed image -->

### Finding 2 — Obfuscated Command
- **Event ID:** 4688
- **Encoded Payload:** `<!-- paste base64 string -->`
- **Screenshot:** <!-- add link or embed image -->

### Finding 3 — Scheduled Task Persistence
- **Event ID:** 4698
- **Task Name:** `<!-- fill in -->`
- **Task Command:** `<!-- fill in -->`
- **Screenshot:** <!-- add link or embed image -->

### Finding 4 — Registry Run Key
- **Event ID:** Sysmon 13
- **Registry Path:** `<!-- fill in -->`
- **Value Written:** `<!-- fill in -->`
- **Screenshot:** <!-- add link or embed image -->

---

## Detection Gaps Identified

> _Note any techniques that did NOT generate alerts and why._

- Example: Script Block Logging was not enabled initially — encoded commands were not fully visible until Event ID 4104 was activated.

---

## Recommendations

1. Enable PowerShell Script Block Logging via Group Policy
2. Create Sentinel Analytic Rules for scheduled task creation (Event ID 4698)
3. Alert on any PowerShell process using `-enc` or `-encodedcommand`
4. Monitor registry writes to `CurrentVersion\Run` and `CurrentVersion\RunOnce`
5. Deploy Sysmon on all Windows endpoints with a hardened config

---

## References

- [MITRE ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK T1053.005](https://attack.mitre.org/techniques/T1053/005/)
- [MITRE ATT&CK T1547.001](https://attack.mitre.org/techniques/T1547/001/)
- [MITRE ATT&CK T1027](https://attack.mitre.org/techniques/T1027/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
