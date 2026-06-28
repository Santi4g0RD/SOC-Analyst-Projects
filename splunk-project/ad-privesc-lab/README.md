# AD Privilege Escalation Lab

## Detection Engineering Project

**Analyst:** Santiago Abel Ruiz Diaz
**Platform:** Wazuh 4.12.0 EDR · Splunk Enterprise 10.4.0 · OPNsense Suricata (ET Open) · Zeek NSM
**Status:** Complete — full attack chain simulated and validated across four detection layers
**MITRE Coverage:** T1046 · T1087.002 · T1110.003 · T1021.001 · T1098 · T1558.003 · T1003.006 · T1053.005 · T1547.001 · T1059.001 · T1027 · T1558.001

A two-hop ACL privilege escalation chain against a live Active Directory domain. Starting with no credentials, the attacker discovers a misconfigured GenericWrite ACL through BloodHound, weaponizes it via targeted Kerberoasting, and escalates to full domain compromise via DCSync. Ends with a multi-technique persistence phase covering scheduled tasks, registry run keys, obfuscated PowerShell, and a Golden Ticket.

Each technique is validated across four independent detection layers — Wazuh EDR, Splunk, Suricata, and Zeek NSM — with blind spots documented where they exist.

---

## Lab Environment

```
  ╔══════════════════════════════════════════════════════════════════════╗
  ║  AD PRIVILEGE ESCALATION LAB  —  soclab.local  —  VLAN-segmented   ║
  ║  Proxmox pve1 (i5-4570, 31 GB)  +  pve2 (32 GB)  —  TL-SG108E    ║
  ╚══════════════════════════════════════════════════════════════════════╝

  ╔═══════════════════════════════════════════════════╗
  ║  VLAN 30 — ATTACKERS   10.10.30.0/24             ║
  ║  VM 202  voldemort (Kali)  10.10.30.100  pve1    ║
  ╚═══════════════════════╦═══════════════════════════╝
                          ║ attack traffic
                          ▼
  ┌───────────────────────────────────────────────────┐
  │  VM 201  OPNsense  —  inter-VLAN router           │
  │  Suricata IDS (ET Open)                           │
  │  VLAN 10 GW 10.10.10.1  VLAN 20 GW 10.10.20.1   │
  │  VLAN 30 GW 10.10.30.1  VLAN 40 GW 10.10.40.1   │
  └──────────╦──────────────────────────╦─────────────┘
             ║                          ║
             ▼                          ▼
  ╔══════════════════════╗   ╔══════════════════════════════╗
  ║  VLAN 10 — SERVERS   ║   ║  VLAN 20 — DETECTION        ║
  ║  10.10.10.0/24       ║   ║  10.10.20.0/24               ║
  ║                      ║   ║                              ║
  ║  ws01   10.10.10.10  ║   ║  splunk  10.10.20.50  pve1  ║
  ║  pve1   domain user  ║   ║  zeek    10.10.20.30  pve1  ║
  ║                      ║   ║  wazuh   10.10.20.20  pve2  ║
  ║  win-dc 10.10.10.11  ║   ╚══════════════════════════════╝
  ║  pve2   soclab.local ║
  ╚══════════════════════╝

  Wazuh agents  (win-dc, ws01)  ──►  wazuh   10.10.20.20   port 1514
  Splunk UF     (win-dc, ws01)  ──►  splunk  10.10.20.50   index=wineventlog
  Suricata alerts               ──►  splunk  10.10.20.50   index=opnsense
  Zeek (switch hardware SPAN)   ──►  splunk  10.10.20.50   index=zeek

  VLAN 40 — MANAGEMENT  10.10.40.0/24
  pve1 10.10.40.201 · pve2 10.10.40.202 · desk1 10.10.40.102 · desk2 10.10.40.103
```

**Four detection layers per technique:**
- **Layer 1 — Wazuh EDR:** host-based alert from agents on win-dc and ws01
- **Layer 2 — Splunk:** SPL against Windows Security log and Sysmon events (`index=wineventlog`)
- **Layer 3 — Suricata:** network IDS alert from OPNsense at the VLAN boundary (`index=opnsense`)
- **Layer 4 — Zeek:** network metadata from full traffic mirror (`index=zeek`)

---

## ACL Attack Path

```
agarcia  ──GenericWrite──►  mbrown  ──DS-Replication──►  Domain
(standard user, spray hit)  (service account, SPN set)   (full NTDS dump)
```

---

## Domain Users

| Account | Password | Role |
|---|---|---|
| agarcia | Spring2025! | Standard user — spray target, GenericWrite over mbrown |
| mbrown | Password123! | Service account — SPN: HTTPSvc/fake.soclab.local:8080, DS-Replication rights |
| lwilson | Spring2025! | Standard user — filler |
| dbaker | Spring2025! | Standard user — filler |

---

## Attack Chain

| Phase | Technique | MITRE | Status |
|---|---|---|---|
| 1.1 | Port scan — full subnet discovery | T1046 | ✅ |
| 1.2 | User enumeration (RID brute / anon LDAP) | T1087.002 | ✅ |
| 2.1 | Password spray → agarcia | T1110.003 | ✅ |
| 3.1 | RDP lateral movement to ws01 as agarcia | T1021.001 | ✅ |
| 4.1 | BloodHound — ACL path discovery | T1087.002 | ✅ |
| 5.1 | GenericWrite → add SPN to mbrown → Kerberoast | T1098 / T1558.003 | ✅ |
| 5.2 | Offline hash crack (hashcat -m 13100) | T1110.002 | ✅ |
| 6.1 | DCSync as mbrown | T1003.006 | ✅ |
| 7.1 | Scheduled task persistence | T1053.005 | ✅ |
| 7.2 | Registry run key | T1547.001 | ✅ |
| 7.3 | Obfuscated PowerShell | T1059.001 + T1027 | ✅ |
| 7.4 | Golden Ticket | T1558.001 | ✅ |

---

## Related

- [`credential-attack-detection/`](../credential-attack-detection/) — same infrastructure, brute force and password spray across Windows SMB and Linux SSH
- [`lab-infrastructure/`](../lab-infrastructure/) — Proxmox, OPNsense, Splunk, Wazuh build notes
