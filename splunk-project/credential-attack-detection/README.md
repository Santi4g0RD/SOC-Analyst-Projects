# Credential Attack Detection — Windows & Linux
## Detection Engineering Project

**Analyst:** Santiago Abel Ruiz Diaz
**Project ID:** SIEM-2026-0613-CRED
**Platform:** Splunk Enterprise 10.4.0
**Status:** Complete — both detections validated against live attack traffic
**MITRE Coverage:** T1110.001 (Brute Force) · T1110.003 (Password Spray)

Runs on top of the [lab infrastructure](../lab-infrastructure/) — OPNsense firewall, Splunk SIEM, a Windows Server 2025 target, and a Kali Purple SSH target, all isolated on a dedicated attacker VLAN.

---

## Goal

Simulate brute force and password spray attacks against a Windows host and a Linux host, then write and validate Splunk detections that tell the two attack patterns apart — even when both come from the same attacker IP.

| Attribute | Brute Force | Password Spray |
|---|---|---|
| Accounts targeted | One | Many |
| Passwords tried | Many per account | One per account |
| Detection signal | High failure count per account | High unique-account count per source |
| Threshold used here | `failure_count >= 10` in 5 min | `unique_accounts >= 5` in 10 min |

---

## Windows — NetExec over SMB

```bash
# Brute force: many passwords against one account
netexec smb 192.168.10.10 -u administrator -p ~/lab/bf-passwords.txt --local-auth

# Password spray: one password against many accounts
netexec smb 192.168.10.10 -u ~/lab/users.txt -p 'Summer2024!' --local-auth --continue-on-success --no-bruteforce
```

`--local-auth` is required — win-target is a workgroup machine, not domain-joined. Without it, NetExec attempts NTLM domain auth and every connection times out (this took a few rounds of troubleshooting Windows Firewall, Defender real-time protection, and account lockout before landing on the actual cause).

**Detection query:**

```spl
index=wineventlog EventCode=4625
| eval username=mvindex(Account_Name, -1)
| stats count as failure_count, dc(username) as unique_accounts by Source_Network_Address
| where failure_count > 5
```

**Result:** 31 EventCode 4625 failures, 6 unique accounts, all from 192.168.20.100. Both `windows/brute-force.spl` and `windows/password-spray.spl` fire on the same row since both attacks ran from the same attacker IP and landed in the same bucket window — the brute force detection catches the high failure count, the spray detection catches the unique account count.

**Field name gotcha (Windows Server 2025 + Splunk UF 9.x):** the generic field names assumed when first writing these detections didn't match what Splunk's Windows TA actually extracts.

| Field | Correct name | Note |
|---|---|---|
| Username | `Account_Name` | Multi-value — must use `mvindex(Account_Name, -1)` |
| Source IP | `Source_Network_Address` | Not `IpAddress` |
| Logon type | `Logon_Type` | Not `LogonType` |

---

## Linux — Hydra over SSH

```bash
# Brute force: many passwords against one account
hydra -l kali -P ~/lab/bf-passwords.txt ssh://192.168.10.181 -t 4

# Password spray: one password against many accounts
hydra -L ~/lab/users.txt -p 'Summer2024!' ssh://192.168.10.181 -t 4
```

**Detection query:**

```spl
index=linux_secure sshd ("Failed password" OR "Invalid user")
| rex field=_raw "Failed password for (?:invalid user )?(?P<target_user>\S+) from (?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port (?P<src_port>\d+)"
| rex field=_raw "Invalid user (?P<invalid_user>\S+) from (?P<src_ip_inv>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port"
| eval src_ip=coalesce(src_ip, src_ip_inv), target_user=coalesce(target_user, invalid_user)
| bucket _time span=10m
| stats count as failure_count, dc(target_user) as unique_accounts by _time, src_ip
```

**Result:** 21 failed SSH logons, 6 unique accounts, from 192.168.20.100. Run a few minutes apart, the two attacks landed in *separate* 5-minute buckets — the brute force detection caught a clean 10-failures/1-account window, and a clean 11-failures/5-accounts window. The wider 10-minute spray detection merged both into a single 21-failures/6-accounts row. Good illustration of why bucket window size matters: too narrow and a slow spray fragments below threshold; too wide and you lose the ability to tell a brute force apart from a spray sharing the same IP.

**Gotcha:** `splunk add monitor` on the Kali Purple forwarder didn't write to `etc/system/local/inputs.conf` as expected — it landed in `etc/apps/search/local/inputs.conf`, with a typo (`index = linux_secur` instead of `linux_secure`). Splunk gives no error when events route to a non-existent index — they're silently dropped. The forwarder connection and source file both looked perfectly healthy the whole time. Caught by grepping every `inputs.conf` under `etc/apps/*/local/` for the actual monitor stanza.

---

## Validated Detections

| Detection | File | Result |
|---|---|---|
| Windows Brute Force | [`windows/brute-force.spl`](windows/brute-force.spl) | ✅ Fired — 31 failures, 1 account |
| Windows Password Spray | [`windows/password-spray.spl`](windows/password-spray.spl) | ✅ Fired — 6 unique accounts |
| Linux SSH Brute Force | [`linux/brute-force.spl`](linux/brute-force.spl) | ✅ Fired — 10 failures, 1 account |
| Linux SSH Password Spray | [`linux/password-spray.spl`](linux/password-spray.spl) | ✅ Fired — 6 unique accounts (21 failures merged) |

---

## Remediation Recommendations

**Immediate:** Block the offending source IP, reset credentials for any account with a successful logon (4624 / `Accepted password`) within 5 minutes of a failure burst from the same IP, preserve logs on any host the attacker reached.

**Hardening:** Enable account lockout policy (5 failures → 30 min lockout), deploy `fail2ban` on SSH hosts, enforce key-based SSH auth only (`PasswordAuthentication no`), disable `root` SSH login, set up Splunk alerts on both detections (`Save As → Alert`, trigger on `Number of Results > 0`).

**Strategic:** MFA on all interactive/remote logons — this alone eliminates password spray as an effective initial access vector.

---

## Related

- [`lab-infrastructure/`](../lab-infrastructure/) — the Proxmox/OPNsense/Splunk build this runs on
- [`future-work/`](../future-work/) — firewall/IDS-layer detections and extended attack-tool reference, not yet validated
