# Credential Attack Detection Lab

## Detection Engineering Project

**Analyst:** Santiago Abel Ruiz Diaz  
**Platform:** Wazuh 4.12.0 EDR · Splunk Enterprise 10.4.0 · OPNsense Suricata (ET Open) · Zeek NSM  
**Status:** Complete — four attack phases simulated and validated across four detection layers  
**MITRE Coverage:** T1110.001 (Brute Force) · T1110.003 (Password Spray)

Brute force and password spray attacks against Windows (SMB) and Linux (SSH) targets, with detection validated across four independent layers. The lab is designed to surface the key difference between the two attack patterns — and to document exactly where each detection layer sees the attack and where it goes blind.

---

## Lab Infrastructure

```
  ╔══════════════════════════════════════════════════════════════════════╗
  ║  SOCLAB  —  Proxmox pve1 (i5-4570, 31 GB)  +  pve2 (32 GB)        ║
  ║  TL-SG108E managed switch  —  hardware SPAN port 8 → Zeek          ║
  ╚══════════════════════════════════════════════════════════════════════╝

  ╔═══════════════════════════════════════════════╗
  ║  VLAN 30 — ATTACKERS   10.10.30.0/24         ║
  ║  voldemort (Kali)       10.10.30.100  pve1   ║
  ╚═══════════════════════╦═══════════════════════╝
                          ║
                          ▼
  ┌─────────────────────────────────────────────┐
  │  OPNsense  —  inter-VLAN router             │
  │  Suricata IDS (ET Open ruleset)             │
  └──────────╦──────────────────────╦───────────┘
             ║                      ║
             ▼                      ▼
  ╔══════════════════════╗   ╔══════════════════════════════╗
  ║  VLAN 10 — SERVERS   ║   ║  VLAN 20 — DETECTION        ║
  ║  10.10.10.0/24       ║   ║  10.10.20.0/24               ║
  ║                      ║   ║                              ║
  ║  win-dc  10.10.10.11 ║   ║  splunk  10.10.20.50  pve1  ║
  ║  pve2    soclab.local║   ║  zeek    10.10.20.30  pve1  ║
  ║                      ║   ║  wazuh   10.10.20.20  pve2  ║
  ║  ubuntu-vm 10.10.10.100  ╚══════════════════════════════╝
  ║  pve2    SSH target  ║
  ╚══════════════════════╝

  Four detection layers per technique:
  Wazuh EDR  ──►  host-based alerts (Wazuh agents on win-dc, ubuntu-vm)
  Splunk     ──►  SPL against wineventlog + linux_secure indexes
  Suricata   ──►  network IDS at the inter-VLAN boundary (index=opnsense)
  Zeek NSM   ──►  full traffic metadata via hardware SPAN (index=zeek)
```

---

## Targets

| Host | IP | OS | Wazuh Agent | Splunk UF | Zeek Visibility |
|---|---|---|---|---|---|
| win-dc | 10.10.10.11 | Windows Server 2025 | ✅ v4.12.0 | ✅ wineventlog | ✅ cross-node (pve2) |
| ubuntu-vm | 10.10.10.100 | Ubuntu 26.04 LTS | ✅ v4.14.5 | ✅ auth.log → linux_secure | ✅ cross-node (pve2) |

Both targets are on pve2; Kali is on pve1. All attack traffic is cross-node — captured by Zeek's hardware SPAN — and inter-VLAN — seen by Suricata at the OPNsense boundary.

---

## Attack Chain

| Phase | Target | Tool | Technique | MITRE |
|---|---|---|---|---|
| 1 | win-dc SMB | NetExec | Brute force — `administrator` + full password list | T1110.001 |
| 2 | win-dc SMB | NetExec | Password spray — all domain users + wrong/correct password | T1110.003 |
| 3 | ubuntu-vm SSH | Hydra | Brute force — `root` + full password list | T1110.001 |
| 4 | ubuntu-vm SSH | Hydra | Password spray — all linux usernames + wrong password | T1110.003 |

---

## Detection Coverage

| Phase | Technique | Wazuh | Splunk | Suricata | Zeek |
|---|---|---|---|---|---|
| 1 | Windows SMB brute force | ✅ Rule 60204 lv10 | ✅ EventCode 4625 burst | ❌ | ✅ gssapi,smb,ntlm burst |
| 2 | Windows SMB spray | ✅ Rule 92652 × 3 | ✅ dc(Account_Name) ≥ 3 | ❌ | ✅ NTLM usernames from wire |
| 3 | Linux SSH brute force | ✅ Rule 5557 lv5 | ✅ auth.log Failed password | ❌ | ✅ port 22 burst |
| 4 | Linux SSH spray | ✅ Rule 5712 lv10 | ✅ auth.log Invalid user | ❌ | ✅ port 22 burst |

---

## Key Detection Findings

**Brute force vs. spray: different Wazuh rules fire**

Brute force (many passwords, one account) triggers Rule 60204 — "Multiple Windows Logon Failures" (level 10) — because the failure count per account crosses the threshold. Password spray (one password, many accounts) gives each account exactly one failure — Rule 60204 never fires. The spray is only caught by correlating Rule 92652 successes from the same source across multiple accounts, or by the `dc(Account_Name) >= 3` Splunk query.

**Zeek extracts usernames from NTLM wire traffic**

For SMB attacks, Zeek's NTLM analyzer extracts usernames from NTLM Type 3 authentication messages on the wire. The full spray target list (`agarcia`, `lwilson`, `dbaker`, `mbrown`, `administrator`) is visible in Zeek without any agent on the target. SSH is encrypted after handshake — Zeek sees the connection burst but not the usernames.

**auth.log reveals attacker's knowledge level**

`Failed password for root` (user exists, wrong password — `unix_chkpwd` runs) vs. `Failed password for invalid user sysadmin` (username doesn't exist) distinguishes an attacker targeting a known account from one guessing. SSH's built-in rate limiting (`srclimit_penalise`) also fires against the attacker IP, adding connection delays after a failure burst.

**Suricata is blind to authentication attacks**

ET Open has no rules for SMB or SSH authentication failure patterns. Suricata only fired on Phase 1.1 Nmap reconnaissance (SID 2024364 "ET SCAN Possible Nmap User-Agent Observed"). Authentication-layer attacks at this volume are invisible to signature-based network IDS without custom rules.

---

## Splunk Detections

**Windows SMB brute force — 4625 failure burst:**

```spl
index=wineventlog ComputerName="win-dc.soclab.local" EventCode=4625
| stats count by Account_Name, Source_Network_Address, Failure_Reason
| sort -count
```

**Windows SMB spray — multiple accounts from same source:**

```spl
index=wineventlog ComputerName="win-dc.soclab.local" EventCode=4625
| bucket _time span=1m
| stats dc(Account_Name) as unique_accounts, count by _time, Source_Network_Address
| where unique_accounts >= 3
| sort -_time
```

**Windows — full 4624/4625 view from attacker IP:**

```spl
index=wineventlog ComputerName="win-dc.soclab.local" (EventCode=4624 OR EventCode=4625)
  Source_Network_Address="10.10.30.100"
| table _time, EventCode, Account_Name, Source_Network_Address, Logon_Type
| sort -_time
```

**Linux SSH failures from auth.log:**

```spl
index=linux_secure host="ubuntu-vm"
| search _raw="*10.10.30.100*"
| table _time, _raw
| sort -_time
```

**Zeek — SMB burst with NTLM usernames:**

```spl
index=zeek sourcetype=zeek_json
| spath input=_raw
| search "id.orig_h"="10.10.30.100" "id.resp_h"="10.10.10.11"
| table _time, "id.orig_h", "id.resp_h", "id.resp_p", service, username
| sort -_time
```

**Zeek — SSH burst:**

```spl
index=zeek sourcetype=zeek_json
| spath input=_raw
| search "id.orig_h"="10.10.30.100" "id.resp_h"="10.10.10.100"
| table _time, "id.orig_h", "id.resp_h", "id.resp_p", service
| sort -_time
```

---

## Field Name Reference

| Field | Windows (wineventlog) | Linux (linux_secure) |
|---|---|---|
| Source IP | `Source_Network_Address` (not `IpAddress`) | parsed from `_raw` |
| Username | `Account_Name` | parsed from `_raw` |
| Failure reason | `Failure_Reason` | "invalid user" vs "Failed password" in raw line |

---

## Related

- [`ad-privesc-lab/`](../ad-privesc-lab/) — same infrastructure, AD privilege escalation chain
- [`lab-infrastructure/`](../lab-infrastructure/) — Proxmox, OPNsense, Splunk, Wazuh build notes
