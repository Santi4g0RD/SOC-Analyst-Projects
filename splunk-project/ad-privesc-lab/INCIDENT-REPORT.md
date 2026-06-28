# Incident Report — AD Privilege Escalation / Full Domain Compromise

**ID:** IR-2026-001  
**Date:** 2026-06-27  
**Analyst:** Santiago Abel Ruiz Diaz  
**Severity:** Critical  
**Status:** Contained (simulated lab environment)

---

## What Happened

An attacker with no initial credentials gained full domain admin on `soclab.local` in under 5 hours through a chain of misconfigurations — no exploits required. Entry point was a weak password on a standard domain account (`agarcia`). From there, a misconfigured ACL gave write access over a service account (`mbrown`), which had DS-Replication rights. Once those rights were abused, the domain's `krbtgt` hash was extracted and a Golden Ticket was forged.

The attack went from zero to SYSTEM on the domain controller via password spray → lateral movement → BloodHound enumeration → Kerberoasting → DCSync → Golden Ticket.

---

## Detection Timeline

All times 2026-06-27.

| Time | Event | Source |
|---|---|---|
| 13:34 | Null session attempt against `win-dc` (SMB + LDAP) | Wazuh Rule 92652 |
| 13:58 | RDP password spray — `agarcia` hit | Wazuh Rules 60122 + 92652 |
| 14:27 | RDP session opened to `ws01` as `SOCLAB\agarcia` | Wazuh Rule 92653 / Splunk 4624 Logon_Type=10 |
| 14:49 | `SharpHound.exe` written to `ws01` desktop by PowerShell | Wazuh Rule 92203 / Sysmon EventCode 11 |
| 15:42 | BloodHound enumeration — burst on ports 135, 389, 445, 636, 3268 from `ws01` | Zeek (Global Catalog port 3268 is the key signal) |
| 16:10 | Kerberoasting — TGS requested for `mbrown` with RC4 encryption (`0x17`) | Splunk EventCode 4769 |
| 16:43 | DCSync — `mbrown` pulled `krbtgt` hash via DS-Replication | Splunk EventCode 4662 / Zeek dynamic RPC port 49679 |
| 17:08 | Registry run key written to `HKLM\...\CurrentVersion\Run\WindowsUpdate` | Wazuh Rule 92302 / Sysmon EventCode 13 |
| 17:35 | Scheduled task `\WindowsUpdate` created, triggers at logon, runs as SYSTEM | Wazuh Rule 60228 / Splunk EventCode 4698 |
| 18:11 | Obfuscated PowerShell beacon — base64 encoded, child PS process, outbound to 10.10.30.100:9001 | Wazuh Rule 92027 / Splunk EventCode 4104 |
| 18:40 | Golden Ticket forged using `krbtgt` AES256 — SYSTEM shell on `win-dc` via psexec | Wazuh Rule 92650 (lv12) / Splunk 4624+4672, no preceding 4768 |

First high-confidence alert was 13:34 (anonymous null session). Full domain compromise was 16:43 (DCSync). That's roughly 3 hours from first noisy recon to game over.

---

## Affected Systems and Accounts

**Systems:**
- `ws01.soclab.local` (10.10.10.10) — compromised via RDP, used as pivot
- `win-dc.soclab.local` (10.10.10.11) — DCSync target, SYSTEM shell via Golden Ticket

**Accounts:**
- `agarcia` — initial access via password spray (`Spring2025!`)
- `mbrown` — Kerberoasted, RC4 hash cracked, DS-Replication abused
- `krbtgt` — hash extracted, used to forge Golden Ticket — **this is the critical one**
- `Administrator` — Golden Ticket was forged in this name

---

## Root Causes

Three misconfigurations made this chain possible:

1. **Weak password on `agarcia`** — seasonal password, first hit on a spray with common pattern. No lockout policy in place.
2. **GenericWrite ACL from `agarcia` → `mbrown`** — a standard domain user had write access over a service account. BloodHound found it in minutes.
3. **`mbrown` had DS-Replication-Get-Changes-All** — a service account with domain replication rights and a crackable SPN is the worst combination in AD.

RC4 being enabled on `mbrown` made the Kerberoast practical — AES256-only accounts are not crackable offline.

---

## Detection Gaps

A few things were blind or late:

- **BloodHound LDAP enumeration** — Splunk had zero EventCode 4662 events for the LDAP queries. `auditpol` alone isn't enough; SACLs need to be set on user/group objects too. Zeek (Global Catalog burst on port 3268) was the only real signal.
- **Kerberoasting tool drop** — Wazuh caught `Rubeus.exe` hitting disk (Rule 92203) but had no coverage on the TGS request itself. Splunk's 4769 with `0x17` was the clean detection.
- **DCSync replication call** — Wazuh caught `mimikatz.exe` drop (Rule 92213, lv15) but missed the actual replication. Splunk's 4662 with Message field GUIDs is the correct detection (not the Properties field — those GUIDs don't appear there on WS2025).
- **Suricata** — blind to most of this chain because ws01 and win-dc share VLAN 10 and traffic never crosses OPNsense.

---

## Containment Steps

In order:

1. **Isolate `ws01`** — disconnect from network. The attacker has an active RDP session and persistence (scheduled task + run key).
2. **Reset `krbtgt` password twice** — this is the only way to invalidate existing Golden Tickets. First reset starts the clock; second reset (10+ hours later) invalidates any tickets issued with the old key. All Kerberos sessions will break — coordinate with users first.
3. **Reset `agarcia` and `mbrown` passwords** — both are compromised.
4. **Remove `mbrown`'s DS-Replication rights** — check `Active Directory Users and Computers` → domain root → Security → `mbrown`. Remove `Replicating Directory Changes All`.
5. **Remove the GenericWrite ACL from `agarcia` over `mbrown`** — use `Get-ACL` / `Set-ACL` or `dsacls.exe` to confirm and revoke.
6. **Remove persistence from `ws01`** — delete `HKLM\...\CurrentVersion\Run\WindowsUpdate`, delete `\WindowsUpdate` scheduled task.

---

## Recommendations

- **Enforce a lockout policy** — even 10 failed attempts in 10 minutes would have slowed the spray. Currently there's none.
- **Disable RC4 Kerberos domain-wide** — if no legacy systems need it, disable it. AES256-only removes the offline crack path from Kerberoasting entirely.
- **Audit service account ACLs** — `mbrown` shouldn't have GenericWrite exposed to standard users and shouldn't have DS-Replication rights. Run BloodHound quarterly as a defensive audit.
- **Enable Object Access auditing with SACLs** — `auditpol` for Directory Service Access isn't enough. SACLs on user and group objects are required for 4662 events to fire. Without this, LDAP enumeration is invisible to the SIEM.
- **Operationalize the DCSync detection** — a saved Splunk alert on EventCode 4662 with replication GUIDs in the Message field should page immediately. This event has near-zero false positives in a normal environment.
