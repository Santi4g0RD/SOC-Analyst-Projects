# DISA STIG: System Hardening — Windows Server 2025 Controls Automated with PowerShell on Azure

**Author:** Santiago Abel Ruiz Diaz
**Platform:** Microsoft Azure
**Environment:** Windows Server 2025 VM
**Date:** 2026-06-10

---

## Overview

Implemented and verified DISA STIG security controls on a Windows Server 2025 Azure VM using PowerShell. Each script targets a specific STIG finding, applies the required configuration via registry or security policy, and was validated before and after execution.

| # | STIG-ID | Category | Control | Script | Result |
|---|---------|----------|---------|--------|--------|
| 1 | WN25-AU-000500 | Audit & Logging | Security event log ≥ 1024000 KB | [📄](./Win25 Server STIG Scripts/STIG-ID-WN25-AU-000500.ps1) | ⬜ Pending |
| 2 | WN25-AU-000505 | Audit & Logging | Application event log ≥ 32768 KB | [📄](./Win25 Server STIG Scripts/STIG-ID-WN25-AU-000505.ps1) | ⬜ Pending |
| 3 | WN25-AU-000510 | Audit & Logging | System event log ≥ 32768 KB | [📄](./Win25 Server STIG Scripts/STIG-ID-WN25-AU-000510.ps1) | ⬜ Pending |
| 4 | WN25-AC-000005 | Account Policy | Account lockout duration ≥ 15 min | [📄](./Win25 Server STIG Scripts/STIG-ID-WN25-AC-000005.ps1) | ⬜ Pending |
| 5 | WN25-AC-000010 | Account Policy | Account lockout threshold ≤ 3 attempts | [📄](./Win25 Server STIG Scripts/STIG-ID-WN25-AC-000010.ps1) | ⬜ Pending |
| 6 | WN25-AC-000015 | Account Policy | Reset lockout counter ≥ 15 min | [📄](./Win25 Server STIG Scripts/STIG-ID-WN25-AC-000015.ps1) | ⬜ Pending |
| 7 | WN25-SO-000005 | Security Options | Disable built-in Guest account | [📄](./Win25 Server STIG Scripts/STIG-ID-WN25-SO-000005.ps1) | ⬜ Pending |
| 8 | WN25-SO-000070 | Security Options | UAC credential prompt on secure desktop | [📄](./Win25 Server STIG Scripts/STIG-ID-WN25-SO-000070.ps1) | ⬜ Pending |
| 9 | WN25-CC-000035 | Remote Access | Require NLA for Remote Desktop | [📄](./Win25 Server STIG Scripts/STIG-ID-WN25-CC-000035.ps1) | ⬜ Pending |
| 10 | WN25-CC-000040 | Network | Disable SMBv1 protocol | [📄](./Win25 Server STIG Scripts/STIG-ID-WN25-CC-000040.ps1) | ⬜ Pending |

---

## Audit & Logging

### WN25-AU-000500 — Security Event Log Size

**Rule:** The Security event log must be at least 1024000 KB (1 GB).
**Registry:** `HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security`
**Value:** `MaxSize = 1024000`
**Before:**
**After:**
**Result:** ⬜ Pending

![Verify: Before](./screenshots/WN25-AU-000500-before.png)

**Script:** [STIG-ID-WN25-AU-000500.ps1](./Win25 Server STIG Scripts/STIG-ID-WN25-AU-000500.ps1)

![Verify: After](./screenshots/WN25-AU-000500-after.png)

---

### WN25-AU-000505 — Application Event Log Size

**Rule:** The Application event log must be at least 32768 KB (32 MB).
**Registry:** `HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application`
**Value:** `MaxSize = 32768`
**Before:**
**After:**
**Result:** ⬜ Pending

![Verify: Before](./screenshots/WN25-AU-000505-before.png)

**Script:** [STIG-ID-WN25-AU-000505.ps1](./Win25 Server STIG Scripts/STIG-ID-WN25-AU-000505.ps1)

![Verify: After](./screenshots/WN25-AU-000505-after.png)

---

### WN25-AU-000510 — System Event Log Size

**Rule:** The System event log must be at least 32768 KB (32 MB).
**Registry:** `HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System`
**Value:** `MaxSize = 32768`
**Before:**
**After:**
**Result:** ⬜ Pending

![Verify: Before](./screenshots/WN25-AU-000510-before.png)

**Script:** [STIG-ID-WN25-AU-000510.ps1](./Win25 Server STIG Scripts/STIG-ID-WN25-AU-000510.ps1)

![Verify: After](./screenshots/WN25-AU-000510-after.png)

---

## Account Policy

### WN25-AC-000005 — Account Lockout Duration

**Rule:** Account lockout duration must be 15 minutes or greater.
**Method:** secedit — `LockoutDuration = 15`
**Before:**
**After:**
**Result:** ⬜ Pending

![Verify: Before](./screenshots/WN25-AC-000005-before.png)

**Script:** [STIG-ID-WN25-AC-000005.ps1](./Win25 Server STIG Scripts/STIG-ID-WN25-AC-000005.ps1)

![Verify: After](./screenshots/WN25-AC-000005-after.png)

---

### WN25-AC-000010 — Account Lockout Threshold

**Rule:** Account lockout threshold must be 3 or fewer invalid logon attempts.
**Method:** secedit — `LockoutBadCount = 3`
**Before:**
**After:**
**Result:** ⬜ Pending

![Verify: Before](./screenshots/WN25-AC-000010-before.png)

**Script:** [STIG-ID-WN25-AC-000010.ps1](./Win25 Server STIG Scripts/STIG-ID-WN25-AC-000010.ps1)

![Verify: After](./screenshots/WN25-AC-000010-after.png)

---

### WN25-AC-000015 — Reset Account Lockout Counter

**Rule:** Reset account lockout counter must be 15 minutes or greater.
**Method:** secedit — `ResetLockoutCount = 15`
**Before:**
**After:**
**Result:** ⬜ Pending

![Verify: Before](./screenshots/WN25-AC-000015-before.png)

**Script:** [STIG-ID-WN25-AC-000015.ps1](./Win25 Server STIG Scripts/STIG-ID-WN25-AC-000015.ps1)

![Verify: After](./screenshots/WN25-AC-000015-after.png)

---

## Security Options

### WN25-SO-000005 — Guest Account Disabled

**Rule:** The built-in Guest account must be disabled.
**Method:** `Disable-LocalUser -Name "Guest"`
**Before:**
**After:**
**Result:** ⬜ Pending

![Verify: Before](./screenshots/WN25-SO-000005-before.png)

**Script:** [STIG-ID-WN25-SO-000005.ps1](./Win25 Server STIG Scripts/STIG-ID-WN25-SO-000005.ps1)

![Verify: After](./screenshots/WN25-SO-000005-after.png)

---

### WN25-SO-000070 — UAC Elevation Prompt

**Rule:** UAC must prompt administrators for credentials on the secure desktop.
**Registry:** `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
**Value:** `ConsentPromptBehaviorAdmin = 1`
**Before:**
**After:**
**Result:** ⬜ Pending

![Verify: Before](./screenshots/WN25-SO-000070-before.png)

**Script:** [STIG-ID-WN25-SO-000070.ps1](./Win25 Server STIG Scripts/STIG-ID-WN25-SO-000070.ps1)

![Verify: After](./screenshots/WN25-SO-000070-after.png)

---

## Remote Access & Network

### WN25-CC-000035 — Remote Desktop NLA Required

**Rule:** Remote Desktop must require Network Level Authentication (NLA).
**Registry:** `HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`
**Value:** `UserAuthentication = 1`
**Before:**
**After:**
**Result:** ⬜ Pending

![Verify: Before](./screenshots/WN25-CC-000035-before.png)

**Script:** [STIG-ID-WN25-CC-000035.ps1](./Win25 Server STIG Scripts/STIG-ID-WN25-CC-000035.ps1)

![Verify: After](./screenshots/WN25-CC-000035-after.png)

---

### WN25-CC-000040 — Disable SMBv1

**Rule:** SMBv1 protocol must be disabled.
**Method:** `Set-SmbServerConfiguration -EnableSMB1Protocol $false`
**CVEs:** CVE-2017-0144 (EternalBlue / WannaCry)
**Before:**
**After:**
**Result:** ⬜ Pending

![Verify: Before](./screenshots/WN25-CC-000040-before.png)

**Script:** [STIG-ID-WN25-CC-000040.ps1](./Win25 Server STIG Scripts/STIG-ID-WN25-CC-000040.ps1)

![Verify: After](./screenshots/WN25-CC-000040-after.png)

---

## Testing Environment

| Detail | Value |
|--------|-------|
| Platform | Microsoft Azure |
| VM Image | Windows Server 2025 |
| Test Date | |
| Tested By | Santiago Abel Ruiz Diaz |
