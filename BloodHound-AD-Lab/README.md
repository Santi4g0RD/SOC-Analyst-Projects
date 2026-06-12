# BloodHound AD Attack Path Mapping — Windows Server 2025 (lababel.local)

**Author:** Santiago Abel Ruiz Diaz
**LinkedIn:** [santiago-a-ruiz-diaz-4aa418b2](https://www.linkedin.com/in/santiago-a-ruiz-diaz-4aa418b2/)
**GitHub:** [Santi4g0RD](https://github.com/Santi4g0RD)
**Platform:** Microsoft Azure
**Domain:** lababel.local
**DC:** WS25-DC01.lababel.local (Windows Server 2025)
**Date:** 2026-06-12

---

## Overview

After applying DISA STIG hardening controls to a Windows Server 2025 Domain Controller, SharpHound was used to collect Active Directory enumeration data. The results were analyzed in BloodHound CE to identify attack paths, privilege escalation opportunities, and high-risk ACL relationships in the domain.

**Tools used:**
- SharpHound (AD collector, run on DC)
- BloodHound CE (graph analysis, run on Kali Linux via Docker)
- xfreerdp drive redirection (file transfer over RDP — no VPN required)

---

## Environment

| Detail | Value |
| --- | --- |
| Domain | lababel.local |
| Domain Controller | WS25-DC01.lababel.local |
| OS | Windows Server 2025 |
| DC Role | AD DS + DNS |
| Collection Method | SharpHound `-c All` |
| Files Collected | 7 |

---

## Data Collection

SharpHound was transferred to the DC via RDP drive redirection from Kali, avoiding the need for a VPN or additional network exposure. Windows Defender exclusions were added for the lab environment before executing the collector.

```powershell
# On DC — disable Defender AV and run SharpHound
Add-MpPreference -ExclusionPath "C:\STIG"
Add-MpPreference -ExclusionPath "\\tsclient\kali"

Copy-Item \\tsclient\kali\SharpHound.exe C:\STIG\
C:\STIG\SharpHound.exe -c All --outputdirectory C:\STIG\

# Copy ZIP back to Kali over the same RDP drive
Copy-Item "C:\STIG\20260612200245_BloodHound.zip" \\tsclient\kali\
```

---

## AD Graph Overview

![AD Graph Overview](./screenshots/bloodhound-ad-overview.png)

Key objects identified in the domain:

| Object | Type |
| --- | --- |
| LABABEL@LABABEL.LOCAL | User (Domain Admin) |
| DOMAIN ADMINS | Group |
| ENTERPRISE ADMINS | Group |
| ADMINISTRATORS | Group |
| KEY ADMINS | Group |
| ENTERPRISE KEY ADMINS | Group |
| WS25-DC01 | Domain Controller |
| DEFAULT DOMAIN CONTROLLERS POLICY | GPO |

---

## Findings

### Finding 1 — DCSync Rights

![DCSync Rights](./screenshots/bloodhound-dcsync-rights.png)

**Query:** Find Principals with DCSync Rights

| Principal | Rights |
| --- | --- |
| DOMAIN ADMINS | DCSync, AllExtendedRights |
| ADMINISTRATORS | DCSync, AllExtendedRights |
| ENTERPRISE ADMINS | GenericAll |
| WS25-DC01 (computer) | DCSync |

**Risk:** Any account in these groups can execute a DCSync attack using `mimikatz lsadump::dcsync` to dump all domain password hashes — including `krbtgt`. This enables a **Golden Ticket** attack for persistent, undetected domain access even after a password reset.

---

### Finding 2 — Domain Admins Control Over Default DC GPO

![GPO Control](./screenshots/bloodhound-gpo-control.png)

**Query:** Pathfinding — Domain Admins → Default Domain Controllers Policy

`DOMAIN ADMINS` holds four ACL edges over the **Default Domain Controllers Policy** GPO:

| Edge | Meaning |
| --- | --- |
| Owns | Full ownership of the GPO object |
| GenericWrite | Can modify any GPO setting |
| WriteOwner | Can reassign GPO ownership |
| WriteDacl | Can modify GPO ACL permissions |

**Risk:** An attacker who compromises any Domain Admin account can modify the GPO applied to all Domain Controllers — enabling malicious startup scripts, disabling security controls, or creating backdoor accounts that persist across every DC in the domain.

---

### Finding 3 — Shortest Path to Domain Admin

![Shortest Path to DA](./screenshots/bloodhound-path-to-da.png)

**Query:** Pathfinding — LABABEL@LABABEL.LOCAL → DOMAIN ADMINS

`LABABEL@LABABEL.LOCAL` → **MemberOf** → `DOMAIN ADMINS`

**1-hop path.** The user account is a direct member of Domain Admins. Compromising this single credential — via phishing, credential stuffing, or password spray — results in immediate full domain control with no lateral movement required.

---

### Finding 4 — Shadow Credentials Attack Surface

`KEY ADMINS` and `ENTERPRISE KEY ADMINS` both have **AddKeyCredentialLink** on `WS25-DC01`.

**Risk:** Any member of these groups can add an alternate credential (certificate-based) to the DC's `msDS-KeyCredentialLink` attribute, then authenticate as the DC account without knowing its password. This enables a stealthy privilege escalation path that bypasses traditional password-based defenses.

---

### Finding 5 — Kerberoastable Accounts

**Query:** `MATCH (u:User {hasspn:true}) RETURN u`

**Result:** No results. No service accounts with registered SPNs exist in this environment — no Kerberoasting attack surface.

---

## Summary

| Finding | Severity | Impact |
| --- | --- | --- |
| DCSync rights held by 3 groups + DC | High | Full domain credential dump, Golden Ticket |
| Domain Admins own Default DC GPO | High | GPO abuse → persistent code exec on all DCs |
| Direct DA membership (1-hop path) | High | Full domain compromise via single credential |
| AddKeyCredentialLink on DC | Medium | Shadow Credentials attack from Key Admins groups |
| No Kerberoastable accounts | Informational | No SPN-based attack surface |

---

## Related Projects

- [DISA STIG: Windows Server 2025 Hardening](../Win25%20Server%20STIG%20Project/)
