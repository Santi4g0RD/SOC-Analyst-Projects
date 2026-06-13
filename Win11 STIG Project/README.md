# DISA STIG: System Hardening — Windows 11 Controls Automated with PowerShell on Azure

**Author:** Santiago Abel Ruiz Diaz
**Platform:** Microsoft Azure
**Environment:** Windows 11 VM
**Date:** 2026-06-10

---

## Overview

Implemented and verified DISA STIG security controls on a Windows 11 Azure VM using PowerShell. Each script targets a specific STIG finding, applies the required configuration via registry or security policy, and was validated before and after execution.

| # | STIG-ID | Category | Control | Script | Result |
|---|---------|----------|---------|--------|--------|
| 1 | WN11-AU-000500 | Audit & Logging | Application event log ≥ 32768 KB | [📄](./Window%2011%20STIG%20Scripts/STIG-ID-WN11-AU-000500.ps1) | ✅ Pass |
| 2 | WN11-AU-000505 | Audit & Logging | Security event log ≥ 1024000 KB | [📄](./Window%2011%20STIG%20Scripts/STIG-ID-WN11-AU-000505.ps1) | ✅ Pass |
| 3 | WN11-AU-000510 | Audit & Logging | System event log ≥ 32768 KB | [📄](./Window%2011%20STIG%20Scripts/STIG-ID-WN11-AU-000510.ps1) | ✅ Pass |
| 4 | WN11-AC-000005 | Account Policy | Account lockout duration ≥ 15 min | [📄](./Window%2011%20STIG%20Scripts/STIG-ID-WN11-AC-000005.ps1) | ✅ Pass |
| 5 | WN11-AC-000010 | Account Policy | Account lockout threshold ≤ 3 attempts | [📄](./Window%2011%20STIG%20Scripts/STIG-ID-WN11-AC-000010.ps1) | ✅ Pass |
| 6 | WN11-AC-000015 | Account Policy | Reset lockout counter ≥ 15 min | [📄](./Window%2011%20STIG%20Scripts/STIG-ID-WN11-AC-000015.ps1) | ✅ Pass |
| 7 | WN11-CC-000005 | Component Config | Disable camera access from lock screen | [📄](./Window%2011%20STIG%20Scripts/STIG-ID-WN11-CC-000005.ps1) | ✅ Pass |
| 8 | WN11-CC-000197 | Component Config | Disable voice activation above lock screen | [📄](./Window%2011%20STIG%20Scripts/STIG-ID-WN11-CC-000197.ps1) | ✅ Pass |
| 9 | WN11-SO-000005 | Security Options | Disable built-in Guest account | [📄](./Window%2011%20STIG%20Scripts/STIG-ID-WN11-SO-000005.ps1) | ✅ Pass |
| 10 | WN11-SO-000070 | Security Options | UAC credential prompt on secure desktop | [📄](./Window%2011%20STIG%20Scripts/STIG-ID-WN11-SO-000070.ps1) | ✅ Pass |
| 11 | WN11-CC-000030 | Component Config | Disable Autoplay for non-volume devices | [📄](./Window%2011%20STIG%20Scripts/STIG-ID-WN11-CC-000030.ps1) | ✅ Pass |
| 12 | WN11-SO-000075 | Security Options | Block unencrypted passwords to SMB servers | [📄](./Window%2011%20STIG%20Scripts/STIG-ID-WN11-SO-000075.ps1) | ✅ Pass |

---

## Audit & Logging

### WN11-AU-000500 — Application Event Log Size

**Rule:** Application event log must be at least 32768 KB (32 MB).

**Registry:** `HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application`

**Value:** `MaxSize = 32768`

**Before:** Registry key did not exist (path not found)

**After:** `MaxSize = 32768`

**Result:** ✅ Pass


**Script:** [STIG-ID-WN11-AU-000500.ps1](./Window%2011%20STIG%20Scripts/STIG-ID-WN11-AU-000500.ps1)


---

### WN11-AU-000505 — Security Event Log Size

**Rule:** Security event log must be at least 1024000 KB (1 GB).

**Registry:** `HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security`

**Value:** `MaxSize = 1024000`

**Before:** Registry key did not exist (path not found)

**After:** `MaxSize = 1024000`

**Result:** ✅ Pass


**Script:** [STIG-ID-WN11-AU-000505.ps1](./Window%2011%20STIG%20Scripts/STIG-ID-WN11-AU-000505.ps1)


---

### WN11-AU-000510 — System Event Log Size

**Rule:** System event log must be at least 32768 KB (32 MB).

**Registry:** `HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System`

**Value:** `MaxSize = 32768`

**Before:** Registry key did not exist (path not found)

**After:** `MaxSize = 32768`

**Result:** ✅ Pass


**Script:** [STIG-ID-WN11-AU-000510.ps1](./Window%2011%20STIG%20Scripts/STIG-ID-WN11-AU-000510.ps1)


---

## Account Policy

### WN11-AC-000005 — Account Lockout Duration

**Rule:** Account lockout duration must be 15 minutes or greater.

**Method:** secedit — `LockoutDuration = 15`

**Before:** Lockout duration not configured (0 minutes)

**After:** Lockout duration: 15 minutes

**Result:** ✅ Pass


**Script:** [STIG-ID-WN11-AC-000005.ps1](./Window%2011%20STIG%20Scripts/STIG-ID-WN11-AC-000005.ps1)


---

### WN11-AC-000010 — Account Lockout Threshold

**Rule:** Account lockout threshold must be 3 or fewer invalid logon attempts.

**Method:** secedit — `LockoutBadCount = 3`

**Before:** Lockout threshold not configured (0)

**After:** Lockout threshold: 3 attempts

**Result:** ✅ Pass


**Script:** [STIG-ID-WN11-AC-000010.ps1](./Window%2011%20STIG%20Scripts/STIG-ID-WN11-AC-000010.ps1)


---

### WN11-AC-000015 — Reset Account Lockout Counter

**Rule:** Reset account lockout counter must be 15 minutes or greater.

**Method:** secedit — `ResetLockoutCount = 15`

**Before:** Reset counter not configured (0 minutes)

**After:** Reset counter: 15 minutes

**Result:** ✅ Pass
**Notes:** Covered by the same secedit pass as WN11-AC-000005.

**Script:** *(shared — see [STIG-ID-WN11-AC-000005.ps1](./Window%2011%20STIG%20Scripts/STIG-ID-WN11-AC-000005.ps1))*


---

## Component Configuration

### WN11-CC-000005 — Camera Access from Lock Screen

**Rule:** Camera access from the lock screen must be disabled.

**Registry:** `HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization`

**Value:** `NoLockScreenCamera = 1`

**Before:** Registry key did not exist (path not found)

**After:** `NoLockScreenCamera = 1`

**Result:** ✅ Pass


**Script:** [STIG-ID-WN11-CC-000005.ps1](./Window%2011%20STIG%20Scripts/STIG-ID-WN11-CC-000005.ps1)


---

### WN11-CC-000197 — Voice Activation Above Lock Screen

**Rule:** Windows apps must not be activated by voice while the system is locked.

**Registry:** `HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy`

**Value:** `LetAppsActivateWithVoiceAboveLock = 2` (Force Deny)

**Before:** Registry key did not exist (path not found)

**After:** `LetAppsActivateWithVoiceAboveLock = 2`

**Result:** ✅ Pass


**Script:** [STIG-ID-WN11-CC-000197.ps1](./Window%2011%20STIG%20Scripts/STIG-ID-WN11-CC-000197.ps1)


---

### WN11-CC-000030 — Autoplay for Non-Volume Devices

**Rule:** Autoplay must be turned off for non-volume devices (e.g. cameras, phones).

**Registry:** `HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer`

**Value:** `NoAutoplayfornonVolume = 1`

**Before:** Registry key did not exist (path not found)

**After:** `NoAutoplayfornonVolume = 1`

**Result:** ✅ Pass


**Script:** [STIG-ID-WN11-CC-000030.ps1](./Window%2011%20STIG%20Scripts/STIG-ID-WN11-CC-000030.ps1)


---

## Security Options

### WN11-SO-000005 — Guest Account Disabled

**Rule:** The built-in Guest account must be disabled.

**Method:** `Disable-LocalUser -Name "Guest"`

**Before:** Guest account enabled

**After:** Guest account disabled (Enabled = False)

**Result:** ✅ Pass


**Script:** [STIG-ID-WN11-SO-000005.ps1](./Window%2011%20STIG%20Scripts/STIG-ID-WN11-SO-000005.ps1)


---

### WN11-SO-000070 — UAC Elevation Prompt

**Rule:** UAC must prompt administrators for credentials on the secure desktop.

**Registry:** `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`

**Value:** `ConsentPromptBehaviorAdmin = 1`

**Before:** `ConsentPromptBehaviorAdmin = 5` (prompt for consent, not credentials)

**After:** `ConsentPromptBehaviorAdmin = 1` (prompt for credentials on secure desktop)

**Result:** ✅ Pass


**Script:** [STIG-ID-WN11-SO-000070.ps1](./Window%2011%20STIG%20Scripts/STIG-ID-WN11-SO-000070.ps1)


---

### WN11-SO-000075 — Unencrypted Passwords to Third-Party SMB Servers

**Rule:** Unencrypted passwords must not be sent to third-party SMB servers.

**Registry:** `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters`

**Value:** `EnablePlainTextPassword = 0`

**Before:** `EnablePlainTextPassword` not configured (value not present)

**After:** `EnablePlainTextPassword = 0`

**Result:** ✅ Pass


**Script:** [STIG-ID-WN11-SO-000075.ps1](./Window%2011%20STIG%20Scripts/STIG-ID-WN11-SO-000075.ps1)


---

## Screenshots

Before and after verification screenshots for all 12 controls are available in the [`screenshots/`](./screenshots/) folder.

---

## Testing Environment

| Detail | Value |
|--------|-------|
| Platform | Microsoft Azure |
| VM Image | Windows 11 |
| Test Date | 2026-06-10 |
| Tested By | Santiago Abel Ruiz Diaz |
