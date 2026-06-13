# DISA STIG: System Hardening — Ubuntu Server 24.04 Controls Automated with Bash on Azure

**Author:** Santiago Abel Ruiz Diaz
**LinkedIn:** [santiago-a-ruiz-diaz-4aa418b2](https://www.linkedin.com/in/santiago-a-ruiz-diaz-4aa418b2/)
**GitHub:** [Santi4g0RD](https://github.com/Santi4g0RD)
**Platform:** Microsoft Azure
**Environment:** Ubuntu Server 24.04 LTS VM
**Date:** 2026-06-13

---

## Overview

Implemented and verified 10 DISA STIG security controls on an Ubuntu Server 24.04 Azure VM. Each script targets a specific STIG finding, applies the required configuration via `apt`, PAM, SSH daemon settings, or kernel module configuration, and was validated before and after execution.

| # | STIG-ID | Category | Control | Script | Result |
|---|---------|----------|---------|--------|--------|
| 1 | UBTU-24-010013 | Audit & Logging | Enable and start auditd service | [📄](./Ubuntu%20Server%20STIG%20Scripts/STIG-ID-UBTU-24-010013.sh) | ✅ Pass |
| 2 | UBTU-24-010014 | Audit & Logging | Audit log max file size ≥ 10 MB | [📄](./Ubuntu%20Server%20STIG%20Scripts/STIG-ID-UBTU-24-010014.sh) | ✅ Pass |
| 3 | UBTU-24-213010 | System Hardening | Automatic security updates enabled | [📄](./Ubuntu%20Server%20STIG%20Scripts/STIG-ID-UBTU-24-213010.sh) | ✅ Pass |
| 4 | UBTU-24-215010 | System Hardening | Telnet package removed | [📄](./Ubuntu%20Server%20STIG%20Scripts/STIG-ID-UBTU-24-215010.sh) | ✅ Pass |
| 5 | UBTU-24-232010 | Account Policy | Minimum password length = 15 characters | [📄](./Ubuntu%20Server%20STIG%20Scripts/STIG-ID-UBTU-24-232010.sh) | ✅ Pass |
| 6 | UBTU-24-251010 | System Hardening | USB storage module disabled | [📄](./Ubuntu%20Server%20STIG%20Scripts/STIG-ID-UBTU-24-251010.sh) | ✅ Pass |
| 7 | UBTU-24-255010 | SSH Hardening | SSH session timeout — ClientAliveInterval 600 | [📄](./Ubuntu%20Server%20STIG%20Scripts/STIG-ID-UBTU-24-255010.sh) | ✅ Pass |
| 8 | UBTU-24-412010 | Firewall | UFW enabled — default deny incoming, SSH allowed | [📄](./Ubuntu%20Server%20STIG%20Scripts/STIG-ID-UBTU-24-412010.sh) | ✅ Pass |
| 9 | UBTU-24-654010 | Account Policy | Account lockout after 3 failed attempts — 15 min | [📄](./Ubuntu%20Server%20STIG%20Scripts/STIG-ID-UBTU-24-654010.sh) | ✅ Pass |
| 10 | UBTU-24-654025 | SSH Hardening | SSH root login disabled | [📄](./Ubuntu%20Server%20STIG%20Scripts/STIG-ID-UBTU-24-654025.sh) | ✅ Pass |

---

## Audit & Logging

### UBTU-24-010013 — Enable auditd

**Rule:** The `auditd` service must be installed, enabled at boot, and actively running.
**Config:** `apt-get install -y auditd audispd-plugins && systemctl enable --now auditd`
**Before:** `auditd` was not installed — `systemctl is-enabled` and `is-active` both returned unit-not-found errors.
**After:** `auditd` installed, `enabled` at boot, and `active` (running).
**Result:** ✅ Pass

**Script:** [STIG-ID-UBTU-24-010013.sh](./Ubuntu%20Server%20STIG%20Scripts/STIG-ID-UBTU-24-010013.sh)

---

### UBTU-24-010014 — Audit Log File Size

**Rule:** The audit log max file size must be at least 10 MB.
**Config:** `/etc/audit/auditd.conf` — `max_log_file = 10`
**Before:** `max_log_file = 8` (Ubuntu default — below the STIG minimum).
**After:** `max_log_file = 10`
**Result:** ✅ Pass

**Script:** [STIG-ID-UBTU-24-010014.sh](./Ubuntu%20Server%20STIG%20Scripts/STIG-ID-UBTU-24-010014.sh)

---

## System Hardening

### UBTU-24-213010 — Automatic Security Updates

**Rule:** The system must be configured to automatically install security patches.
**Config:** `apt-get install -y unattended-upgrades` + `/etc/apt/apt.conf.d/20auto-upgrades`
**Before:** `unattended-upgrades` was not enabled — security patches required manual intervention.
**After:** Service enabled at boot; `20auto-upgrades` configured with `Update-Package-Lists "1"` and `Unattended-Upgrade "1"`.
**Result:** ✅ Pass

**Script:** [STIG-ID-UBTU-24-213010.sh](./Ubuntu%20Server%20STIG%20Scripts/STIG-ID-UBTU-24-213010.sh)

---

### UBTU-24-215010 — Remove Telnet

**Rule:** The telnet package must not be installed — telnet transmits credentials in plaintext.
**Config:** `apt-get remove -y telnet telnetd inetutils-telnet`
**Before:** No telnet package installed on this fresh VM — clean baseline confirmed.
**After:** `dpkg -l | grep telnet` returns no output; `apt purge` ensures any residual config is also removed.
**Result:** ✅ Pass

**Script:** [STIG-ID-UBTU-24-215010.sh](./Ubuntu%20Server%20STIG%20Scripts/STIG-ID-UBTU-24-215010.sh)

---

### UBTU-24-251010 — Disable USB Storage

**Rule:** USB mass storage must be disabled to prevent unauthorized data transfer or malicious device insertion.
**Config:** `/etc/modprobe.d/usb-storage.conf` — `install usb-storage /bin/false`
**Before:** `/etc/modprobe.d/usb-storage.conf` did not exist — the `usb-storage` kernel module could load freely.
**After:** Module blacklisted via modprobe config — any attempt to load `usb-storage` is redirected to `/bin/false`.
**Result:** ✅ Pass

**Script:** [STIG-ID-UBTU-24-251010.sh](./Ubuntu%20Server%20STIG%20Scripts/STIG-ID-UBTU-24-251010.sh)

---

## Account Policy

### UBTU-24-232010 — Minimum Password Length

**Rule:** Passwords must be a minimum of 15 characters.
**Config:** `/etc/security/pwquality.conf` — `minlen = 15`
**Before:** `libpam-pwquality` was not installed and `/etc/security/pwquality.conf` did not exist — no password complexity enforcement in place.
**After:** Package installed; `minlen = 15` written to `pwquality.conf` — PAM enforces minimum length on all password changes.
**Result:** ✅ Pass

**Script:** [STIG-ID-UBTU-24-232010.sh](./Ubuntu%20Server%20STIG%20Scripts/STIG-ID-UBTU-24-232010.sh)

---

### UBTU-24-654010 — Account Lockout Policy

**Rule:** Accounts must lock after 3 consecutive failed login attempts and remain locked for at least 15 minutes.
**Config:** `/etc/security/faillock.conf` — `deny = 3`, `unlock_time = 900`
**Before:** `deny` and `unlock_time` were commented out — no account lockout policy active, enabling unlimited brute-force attempts.
**After:** `deny = 3` and `unlock_time = 900` enforced — accounts lock after 3 failures and auto-unlock after 15 minutes.
**Result:** ✅ Pass

**Script:** [STIG-ID-UBTU-24-654010.sh](./Ubuntu%20Server%20STIG%20Scripts/STIG-ID-UBTU-24-654010.sh)

---

## SSH Hardening

### UBTU-24-255010 — SSH Session Timeout

**Rule:** SSH must terminate idle sessions after no more than 10 minutes of inactivity.
**Config:** `/etc/ssh/sshd_config` — `ClientAliveInterval 600`, `ClientAliveCountMax 0`
**Before:** `ClientAliveInterval` and `ClientAliveCountMax` were not set — idle SSH sessions persisted indefinitely, leaving unattended sessions exposed.
**After:** `ClientAliveInterval 600` and `ClientAliveCountMax 0` configured — idle sessions terminated after 10 minutes with no keepalive retries.
**Result:** ✅ Pass

**Script:** [STIG-ID-UBTU-24-255010.sh](./Ubuntu%20Server%20STIG%20Scripts/STIG-ID-UBTU-24-255010.sh)

---

### UBTU-24-654025 — Disable SSH Root Login

**Rule:** Direct SSH login as root must be disabled.
**Config:** `/etc/ssh/sshd_config` — `PermitRootLogin no`
**Before:** `PermitRootLogin prohibit-password` (Ubuntu default) — root login via SSH key was still permitted, which does not satisfy the STIG requirement.
**After:** `PermitRootLogin no` — all SSH root login methods fully disabled.
**Result:** ✅ Pass

**Script:** [STIG-ID-UBTU-24-654025.sh](./Ubuntu%20Server%20STIG%20Scripts/STIG-ID-UBTU-24-654025.sh)

---

## Firewall

### UBTU-24-412010 — Enable UFW Firewall

**Rule:** A host-based firewall must be active with a default deny inbound policy.
**Config:** `ufw allow ssh && ufw default deny incoming && ufw default allow outgoing && ufw --force enable`
**Before:** UFW was installed but inactive — no inbound traffic restrictions in place.
**After:** UFW active; default deny incoming, allow outgoing; SSH (port 22) explicitly permitted before enabling to prevent lockout.
**Result:** ✅ Pass

**Script:** [STIG-ID-UBTU-24-412010.sh](./Ubuntu%20Server%20STIG%20Scripts/STIG-ID-UBTU-24-412010.sh)

---

## Related Projects

- [DISA STIG: Windows Server 2025 Hardening](../Win25%20Server%20STIG%20Project/)
- [DISA STIG: Windows 11 Hardening](../Win11%20STIG%20Project/)
