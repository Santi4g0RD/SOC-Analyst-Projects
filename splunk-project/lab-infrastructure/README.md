# Home Lab Infrastructure

**Analyst:** Santiago Abel Ruiz Diaz
**Platform:** Proxmox 3-node cluster (pve1/pve2/pve3) · OPNsense · 7-VLAN segmented network · hardware SPAN for full traffic capture
**Status:** Active — this is the platform every other project in this portfolio runs on

---

## Overview

A self-hosted Proxmox lab segmented into 7 VLANs behind an OPNsense router: standard IT infrastructure (servers, detection stack, attackers, management) plus two dedicated OT/ICS segments — a Modbus/SCADA process simulation and a BACnet/IP building-automation simulation — under a shared Purdue-model architecture. A TL-SG108E managed switch mirrors every Proxmox node's uplink to a SPAN port feeding Zeek NSM for full packet visibility.

Every attack-detection project in this portfolio ([`ad-privesc-lab/`](../ad-privesc-lab/), [`credential-attack-detection/`](../credential-attack-detection/), [`ot-ics-lab/`](../ot-ics-lab/)) runs on top of this infrastructure.

![Full SOC lab topology — 7 VLANs, 3-node Proxmox cluster, IT + OT/ICS + BACnet](screenshots/soclab_topology_current.svg)

**[Full Topology & Purdue Model Walkthrough →](topology-walkthrough.md)** — live, screenshot-by-screenshot verification of every VLAN and host, including two real infrastructure problems found and fixed along the way.

---

## VLANs

| VLAN | Segment | Subnet | Notes |
|---|---|---|---|
| 10 | Servers | 10.10.10.0/24 | win-dc, win-target — soclab.local AD domain |
| 20 | Detection | 10.10.20.0/24 | Splunk, Wazuh, Zeek, Security Onion, n8n, IRIS |
| 30 | Attackers | 10.10.30.0/24 | Kali |
| 40 | Management | 10.10.40.0/24 | Proxmox cluster nodes, admin workstation |
| 50 | ICSNETWORK | 10.10.50.0/24 | GRFICSv2 process simulation + OpenPLC (Purdue L0–L1) |
| 55 | OTDMZ | 10.10.55.0/24 | ScadaBR HMI + Node-RED BAS supervisor (Purdue L2) |
| 60 | BACNET | 10.10.60.0/24 | 7-device HVAC/BMS simulator |

---

## Detection Stack

| Layer | Role |
|---|---|
| Wazuh EDR | Host-based alerts — agents on win-dc, win-target, and Linux hosts |
| Splunk Enterprise | SPL search across wineventlog, linux_secure, opnsense, zeek indexes — currently license-gated, search unavailable |
| Security Onion | Second, license-free SIEM/NSM — own Elasticsearch/Kibana, Zeek, and Suricata |
| Suricata (OPNsense) | Inline network IDS at every inter-VLAN boundary |
| Zeek NSM | Full traffic metadata via hardware SPAN |
| n8n + IRIS | SOAR automation and case management |

---

## Related Projects

- [`security-onion/`](../security-onion/) — second SIEM/NSM platform, license-free
- [`ot-ics-lab/`](../ot-ics-lab/) — Purdue-model OT/ICS build (GRFICSv2 + OpenPLC + ScadaBR)
- [`ad-privesc-lab/`](../ad-privesc-lab/) — AD attack chain validated across this infrastructure's detection stack
- [`credential-attack-detection/`](../credential-attack-detection/) — brute force / spray detection across Windows and Linux targets
