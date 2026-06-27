# Splunk SOC Lab — Detection Engineering

**Analyst:** Santiago Abel Ruiz Diaz  
**Platform:** Wazuh 4.12.0 EDR · Splunk Enterprise 10.4.0 · OPNsense Suricata (ET Open) · Zeek NSM  
**Infrastructure:** Proxmox two-node cluster · 4-VLAN segmented network · hardware SPAN for full traffic capture

A self-hosted home lab built to practice detection engineering end-to-end: design the infrastructure, simulate real attacks, and validate that every detection layer catches them — or document why it doesn't.

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
  ║  ws01   10.10.10.10  ║   ║  splunk  10.10.20.50  pve1  ║
  ║  pve1   domain user  ║   ║  zeek    10.10.20.30  pve1  ║
  ║                      ║   ║  wazuh   10.10.20.20  pve2  ║
  ║  win-dc 10.10.10.11  ║   ╚══════════════════════════════╝
  ║  pve2   soclab.local ║
  ╚══════════════════════╝

  Four detection layers per technique:
  Wazuh EDR  ──►  host-based alerts (win-dc, ws01 agents)
  Splunk     ──►  SPL against wineventlog + opnsense + zeek indexes
  Suricata   ──►  network IDS at the inter-VLAN boundary
  Zeek NSM   ──►  full traffic metadata via hardware SPAN
```

---

## Projects

### Active

| Project | Techniques | Status |
|---|---|---|
| [`ad-privesc-lab/`](ad-privesc-lab/) | Two-hop ACL privilege escalation — BloodHound → Kerberoasting → DCSync → Golden Ticket | ✅ Complete |

### Coming Soon — New Infrastructure

| Project | Description |
|---|---|
| `credential-attack-detection/` | NetExec brute force + password spray (Windows SMB) · Hydra SSH brute force (Linux) · 4-layer detection + Splunk dashboard |
| `atomic-red-team/` | MITRE ATT&CK technique simulation via Invoke-AtomicRedTeam · Wazuh + Splunk + Suricata + Zeek coverage |

---

## AD PrivEsc Lab — Featured Project

A two-hop ACL privilege escalation chain against a live Active Directory domain. Starting with no credentials, the attacker discovers a misconfigured GenericWrite ACL through BloodHound, weaponizes it via targeted Kerberoasting, and escalates to full domain compromise via DCSync. Ends with a multi-technique persistence phase.

**Attack path:**
```
agarcia  ──GenericWrite──►  mbrown  ──DS-Replication──►  Domain
(spray hit, standard user)  (SPN set, service acct)      (full NTDS dump)
```

**Detection coverage across 12 techniques:**

| Phase | Technique | MITRE | Wazuh | Splunk | Suricata | Zeek |
|---|---|---|---|---|---|---|
| 1.1 | Port scan | T1046 | ❌ | ✅ filterlog 3,041 ports/min | ✅ SID 2024364 Nmap UA | ✅ 121k conn records |
| 1.2 | User enumeration | T1087.002 | ✅ Rule 92652 | ✅ 4624 ANON LOGON | ❌ | ✅ SMB+LDAP burst |
| 2.1 | Password spray | T1110.003 | ✅ Rules 60122+92652 | ✅ 4625 from VLAN 30 | ❌ | ❌ same-node blind |
| 3.1 | RDP lateral movement | T1021.001 | ✅ Rule 92653 | ✅ 4624 Logon_Type=10 | ❌ | ❌ same-node blind |
| 4.1 | BloodHound ACL discovery | T1087.002 | ✅ Rules 92203+92105 | ✅ EventCode 11 file drop | ❌ intra-VLAN | ✅ port 3268 GC burst |
| 5.1 | Kerberoasting (Rubeus) | T1558.003 | ❌ file drop only | ✅ 4769 etype=0x17 | ❌ | ✅ port 88 krbtgt |
| 5.2 | Hash crack | T1110.002 | — | — | — | — |
| 6.1 | DCSync (Mimikatz) | T1003.006 | ✅ Rule 92213 lv15 | ✅ 4662 replication GUIDs | ❌ intra-VLAN | ✅ port 49679 dynamic RPC |
| 7.1 | Scheduled task | T1053.005 | ✅ Rule 60228 | ✅ 4698 full task XML | ❌ | ❌ |
| 7.2 | Registry run key | T1547.001 | ✅ Rules 92302+92041 | ✅ Sysmon EventCode 13 | ❌ | ❌ |
| 7.3 | Obfuscated PowerShell | T1059.001+T1027 | ✅ Rule 92027 | ✅ 4104 decoded payload | ❌ | ❌ same-node blind |
| 7.4 | Golden Ticket | T1558.001 | ✅ Rule 92650 lv12 | ✅ 4624+4672 no 4768 | ❌ | ✅ cifs/win-dc.soclab.local |

→ [`ad-privesc-lab/`](ad-privesc-lab/)
