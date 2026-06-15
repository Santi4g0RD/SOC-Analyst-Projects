# Splunk Threat Detection: Credential-Based Attacks
## Detection Engineering Project

**Analyst:** Santiago Abel Ruiz Diaz
**Project ID:** SIEM-2026-0613-CRED
**Platform:** Splunk Enterprise / Splunk Cloud
**Severity Coverage:** Critical, High, Medium
**Status:** Detection content ready — queries validated against sample data
**Date:** June 13, 2026
**Data Sources:** `WinEventLog:Security`, `linux_secure`, `OPNsense filterlog`, `Suricata EVE JSON`

---

## Overview

This project delivers eight production-ready SPL detections targeting the two most common credential-based attacks seen in enterprise environments: **brute force** and **password spraying**. Coverage spans Windows Active Directory, Linux SSH, and OPNsense firewall infrastructure, with Suricata IDS correlation providing full kill-chain visibility from initial reconnaissance through credential compromise.

Password spraying and brute force are among the most frequently observed initial access techniques across real-world intrusions. Both abuse legitimate authentication protocols and generate log volume that is easy to miss without tuned detection logic. The key analytical challenge is distinguishing these attacks from normal authentication noise — failed logins happen in every environment. The detections in this project address that challenge through threshold-based statistical analysis, behavioral profiling, and success correlation queries that confirm whether an attack landed.

The lab is built around an OPNsense firewall with Kali Linux on an isolated attacker VLAN. All attack traffic passes through OPNsense before reaching targets, giving the firewall and Suricata IDS first visibility — often detecting reconnaissance before the credential attack begins. Endpoint logs from Windows and Linux targets provide authentication-level detail that the firewall cannot see. Splunk correlates all three data sources to reconstruct the full attack timeline.

Detections are written as standalone SPL files with inline documentation and tuning guidance. Sample log data is included for each scenario to allow immediate testing without a live attack environment.

---

## Detection Content

### Endpoint Detections

| Detection | File | Data Source | MITRE ID | Trigger |
|---|---|---|---|---|
| Windows Brute Force | `detections/windows/brute-force.spl` | WinEventLog:Security | T1110.001 | >= 10 failures, 1 account, 5 min window |
| Windows Password Spray | `detections/windows/password-spray.spl` | WinEventLog:Security | T1110.003 | >= 5 unique accounts, 1 source, 10 min window |
| Linux SSH Brute Force | `detections/linux/brute-force.spl` | linux_secure | T1110.001 | >= 10 failures, 1 account, 5 min window |
| Linux SSH Password Spray | `detections/linux/password-spray.spl` | linux_secure | T1110.003 | >= 5 unique accounts, 1 source, 10 min window |

### Firewall / IDS Detections (OPNsense)

| Detection | File | Data Source | MITRE ID | Trigger |
|---|---|---|---|---|
| Firewall Brute Force | `detections/opnsense/firewall-brute-force.spl` | filterlog | T1110.001 | >= 10 TCP conns to port 22/3389, 5 min window |
| Firewall Password Spray | `detections/opnsense/firewall-spray.spl` | filterlog | T1110.003 | >= 3 unique hosts on port 445/5985, 10 min window |
| Port Scan / Recon | `detections/opnsense/port-scan.spl` | filterlog | T1046, T1595 | >= 15 unique dest ports, 1 source, 2 min window |
| Suricata Alert Correlation | `detections/opnsense/suricata-alerts.spl` | Suricata EVE JSON | Multiple | Signature-based + kill-chain join |

### Detection Layer Coverage

```
Kill chain stage:    Recon         →    Attack           →    Compromise
                     ──────────────     ─────────────────     ─────────────────
Firewall (OPNsense): port-scan.spl      firewall-brute-force.spl
                                        firewall-spray.spl
Suricata IDS:        suricata-alerts    suricata-alerts
Endpoint (Windows):                     brute-force.spl       4624 correlation
                                        password-spray.spl    4624 correlation
Endpoint (Linux):                       brute-force.spl       Accepted password
                                        password-spray.spl    Accepted password
```

---

## Key Concepts

### Brute Force vs. Password Spray

Understanding the behavioral difference is essential for writing accurate detections. Both attacks target authentication but operate on opposite axes:

| Attribute | Brute Force | Password Spray |
|---|---|---|
| Accounts targeted | One (or few) | Many |
| Passwords tried | Many per account | One (or few) per account |
| Rate | High (as fast as possible) | Low-and-slow (evades lockout) |
| Lockout risk | Triggers lockout quickly | Designed to stay below lockout threshold |
| Detection signal | High failure count per account | High unique account count per source |
| Primary indicator | `count >= 10` per account | `dc(account) >= 5` per source |

The detection logic exploits these behavioral differences directly. A spray is fingerprinted by the ratio of unique accounts to total failures — when `avg_attempts_per_account <= 3`, the attacker is trying the same password once or twice per user, which is the hallmark of a spray campaign.

### Windows Event IDs Used

| Event ID | Description | Relevance |
|---|---|---|
| 4625 | Failed logon | Primary signal for both detections |
| 4624 | Successful logon | Used in success correlation to confirm spray/brute hit |
| 4740 | Account locked out | Corroborating signal — confirms brute force threshold hit |
| 4776 | NTLM credential validation failure | Alternative to 4625 for NTLM auth failures |

**Logon Types filtered:**
- `3` — Network logon (SMB, shared resources, domain auth)
- `7` — Workstation unlock
- `10` — RemoteInteractive (RDP)

**SubStatus codes in sample data:**
- `0xC000006A` — Wrong password (account exists, password incorrect)
- `0xC0000064` — Account does not exist
- `0xC0000234` — Account locked out

### Linux Log Patterns Used

```
Failed password for <user> from <ip> port <port> ssh2
Failed password for invalid user <user> from <ip> port <port> ssh2
Invalid user <user> from <ip> port <port>
Accepted password for <user> from <ip> port <port> ssh2
Accepted publickey for <user> from <ip> port <port> ssh2
```

`Invalid user` is a higher-severity signal than `Failed password` — it indicates the attacker is probing for usernames that do not exist, suggesting active enumeration (T1592 — Gather Victim Identity Information) before or alongside the password attack.

---

## Environment Setup

### Lab Topology

```
  Kali (192.168.20.5) ──OPT1──▶ OPNsense Firewall ──LAN──▶ Windows (192.168.10.10)
  [Attacker VLAN]                [192.168.10.1]              Linux   (192.168.10.20)
                                 [Suricata IDS]              Splunk  (192.168.10.100)
                                       │
                                  syslog :514
                                       ▼
                                    Splunk
```

All attack traffic passes through OPNsense. Kali is on a dedicated OPT1 VLAN (192.168.20.0/24) — see `setup/opnsense-splunk-setup.md` for full topology, VM configuration, firewall rules, Suricata setup, and syslog forwarding.

### Index and Sourcetype Configuration

**Windows:**
```
Index:      wineventlog
Sourcetype: WinEventLog:Security
Input:      Splunk Universal Forwarder on Windows hosts, or Windows Event Log input
```

**Linux:**
```
Index:      linux_secure
Sourcetype: linux_secure
Input:      Monitor /var/log/auth.log (Debian/Ubuntu) or /var/log/secure (RHEL/CentOS)
```

**OPNsense:**
```
Index:      opnsense
Sourcetype: syslog
Input:      UDP 514 — OPNsense syslog forwarding (filterlog + Suricata EVE JSON)
```

### Testing with Sample Data

1. In Splunk Web: **Settings → Add Data → Upload**
2. Upload `sample-data/windows-security-events.log`
   - Set sourcetype: `WinEventLog:Security`
   - Set index: `wineventlog`
3. Upload `sample-data/linux-auth.log`
   - Set sourcetype: `linux_secure`
   - Set index: `linux_secure`
4. Open the Search & Reporting app and paste queries from the `detections/` files

The sample data includes four scenarios with realistic timing, event structure, and both attack and baseline traffic. Scenarios include a spray success (Windows), a brute force with account lockout (Windows), a brute force success (Linux), a spray success (Linux), and username enumeration followed by focused brute force (Linux).

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Detection File |
|---|---|---|---|
| Reconnaissance | Active Scanning | T1595 | `opnsense/port-scan.spl` |
| Reconnaissance | Network Service Discovery | T1046 | `opnsense/port-scan.spl` |
| Reconnaissance | Gather Victim Identity Information | T1592 | `linux/brute-force.spl` (Invalid user pattern) |
| Credential Access | Brute Force: Password Guessing | T1110.001 | `windows/brute-force.spl`, `linux/brute-force.spl`, `opnsense/firewall-brute-force.spl` |
| Credential Access | Brute Force: Password Spraying | T1110.003 | `windows/password-spray.spl`, `linux/password-spray.spl`, `opnsense/firewall-spray.spl` |
| Initial Access | Valid Accounts | T1078 | Correlated via 4624/Accepted password after failure burst |
| Lateral Movement | SMB/Windows Admin Shares | T1021.002 | `opnsense/firewall-spray.spl` (EventCode 5140 escalation) |

---

## Tuning Guidance

### Reducing False Positives

All thresholds are starting points. Every environment differs. Common noise sources and how to suppress them:

**Windows:**
- Service accounts generating auth noise: add `NOT TargetUserName IN ("svc_backup","svc_scan","healthcheck")` before the stats command
- Vulnerability scanners from known IPs: add `NOT src_ip IN ("10.0.0.50","10.0.0.51")` (your scanner IPs)
- Automated logon processes: filter on `AuthenticationPackageName` to exclude `Kerberos` if your environment only uses NTLM for interactive logins

**Linux:**
- Known management IPs (Ansible, monitoring): add `NOT src_ip IN ("10.10.1.10","10.10.1.11")`
- Container orchestration systems that rotate source ports rapidly: filter on source IP ranges rather than individual IPs
- Legitimate automation testing environments: create a lookup table and use `NOT [inputlookup allowed_spray_sources.csv | fields src_ip]`

### Adjusting Thresholds

The default thresholds (10 failures / 5 min for brute force, 5 accounts / 10 min for spray) are conservative and designed to catch attacks early. In high-traffic environments you may need to raise them. In environments with very low baseline failure rates, lowering them catches more.

Monitor the `failure_count` and `unique_accounts` distributions on your baseline traffic for at least 48 hours before tuning thresholds. The 95th percentile of normal activity is a reasonable starting point for alert suppression.

---

## Remediation Recommendations

### Immediate Containment

1. Block the offending source IP at the perimeter firewall and on the host-based firewall
2. Reset credentials for any account that showed a successful logon (EventCode 4624 / `Accepted password`) within 5 minutes of a spray or brute force burst from the same IP
3. Force re-authentication for any active sessions from the attacker IP
4. Preserve logs and memory artifacts on any host the attacker successfully authenticated to

### Near-Term Hardening

1. Enable account lockout policy: 5 failed attempts triggers 30-minute lockout (Windows: Default Domain Policy → Account Lockout Policy)
2. Deploy `fail2ban` on Linux SSH hosts with a 10-attempt threshold and 24-hour ban duration
3. Restrict SSH access to known management IP ranges via `/etc/ssh/sshd_config` `AllowUsers` or firewall rules
4. Disable password authentication for SSH entirely where possible — enforce key-based auth only (`PasswordAuthentication no` in `sshd_config`)
5. Disable `root` SSH login: `PermitRootLogin no` in `sshd_config`
6. Set up Splunk alerts for these detections: **Save As → Alert** in the Search app, set trigger condition to `Number of Results > 0`

### Strategic Improvements

1. Implement Multi-Factor Authentication for all interactive and remote logons — MFA eliminates password spray as an effective initial access vector
2. Deploy Microsoft Entra ID (Azure AD) Smart Lockout or equivalent to detect and throttle spray attempts at the identity provider layer
3. Enable Conditional Access policies that restrict logon from unexpected geographies or anonymous/Tor exit node IPs
4. Establish a Privileged Access Workstation (PAW) model — administrative accounts should not be reachable via standard network logon paths
5. Run quarterly password audits using a tool like `DSInternals` or `Invoke-ADPasswordAudit` to identify accounts with weak or commonly sprayed passwords before attackers do

---

## Project Structure

```
splunk-project/
├── README.md                               This file
├── setup/
│   └── opnsense-splunk-setup.md           OPNsense VM setup, VLAN config, Suricata, syslog → Splunk
├── detections/
│   ├── windows/
│   │   ├── brute-force.spl                Windows brute force (EventCode 4625)
│   │   └── password-spray.spl             Windows password spray (EventCode 4625)
│   ├── linux/
│   │   ├── brute-force.spl                Linux SSH brute force (auth.log)
│   │   └── password-spray.spl             Linux SSH password spray (auth.log)
│   └── opnsense/
│       ├── firewall-brute-force.spl       Firewall-level SSH/RDP brute force (filterlog)
│       ├── firewall-spray.spl             Firewall-level SMB spray / multi-host sweep (filterlog)
│       ├── port-scan.spl                  Port scan / recon detection (filterlog)
│       └── suricata-alerts.spl            Suricata IDS correlation + kill-chain join
├── attack-simulation/
│   └── kali-attack-commands.md            Kali attack commands — hydra, netexec, kerbrute, nmap
└── sample-data/
    ├── windows-security-events.log        Sample Windows Security Event XML with 2 attack scenarios
    └── linux-auth.log                     Sample auth.log with 4 attack scenarios + baseline
```

---

## Supporting Documentation

| Document | Description |
|---|---|
| [OPNsense Setup](setup/opnsense-splunk-setup.md) | Full lab setup — VM network adapters, VLANs, firewall rules, Suricata, syslog forwarding to Splunk |
| [Windows Brute Force](detections/windows/brute-force.spl) | SPL detection — EventCode 4625, LogonType filter, severity tiering |
| [Windows Password Spray](detections/windows/password-spray.spl) | SPL detection — spray ratio logic and success correlation query |
| [Linux Brute Force](detections/linux/brute-force.spl) | SPL detection — regex extraction, invalid user percentage scoring |
| [Linux Password Spray](detections/linux/password-spray.spl) | SPL detection — avg_attempts_per_account behavioral fingerprinting |
| [Firewall Brute Force](detections/opnsense/firewall-brute-force.spl) | SPL detection — filterlog parsing, SSH/RDP connection rate, pre-auth visibility |
| [Firewall Spray](detections/opnsense/firewall-spray.spl) | SPL detection — SMB multi-host sweep, lateral movement escalation path |
| [Port Scan](detections/opnsense/port-scan.spl) | SPL detection — unique port count threshold, key port fingerprinting |
| [Suricata Alerts](detections/opnsense/suricata-alerts.spl) | SPL detection — EVE JSON parsing, kill-chain join across all three data sources |
| [Kali Attack Simulation](attack-simulation/kali-attack-commands.md) | Lab commands for hydra, netexec, kerbrute, nmap — maps each tool to logs and detection files |
| [Windows Sample Data](sample-data/windows-security-events.log) | Spray + brute force scenarios with account lockout and logon success events |
| [Linux Sample Data](sample-data/linux-auth.log) | Brute force, spray, enumeration, and baseline scenarios |
