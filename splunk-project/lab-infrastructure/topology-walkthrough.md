# Full Topology & Purdue Model Walkthrough

**Date:** 2026-08-19
**Analyst:** Santiago Abel Ruiz Diaz

A 7-VLAN Proxmox environment: standard SOC infrastructure (servers, detection stack, attacker segment, management) plus two OT segments — an ICS/Modbus process simulation and a BACnet building-automation network — isolated the way real IT/OT boundaries are, not bolted onto a flat lab.

That separation is the point. IT and OT get segmented in production for real reasons — different protocols, different failure tolerance, different incident-response rules.

← Back to [`lab-infrastructure/`](README.md)

---

## Proxmox Cluster — VLAN 40 (Management)

Cluster quorate, all three nodes (pve1/pve2/pve3) online, full VM inventory intact post-outage.

![Proxmox cluster overview](screenshots/topology-walkthrough/01-proxmox-cluster.png)

---

## OPNsense — Firewall / Router / IDS

All interfaces up across every VLAN, and the specific inter-VLAN rules built during earlier sessions (SOAR auto-block alias, OTDMZ egress scoping, OTDMZ↔BACNET) confirmed intact post-reboot.

![OPNsense dashboard — all interfaces up](screenshots/topology-walkthrough/03-opnsense-dashboard.png)
![OPNsense firewall rules intact](screenshots/topology-walkthrough/04-opnsense-rules-a.png)

---

## VLAN 10 — Servers

`win-dc` (soclab.local domain controller): all core AD services running, time sync healthy.
`ws01`: secure channel to the domain confirmed in good condition.

![win-dc — AD services and NTP healthy](screenshots/topology-walkthrough/06-win-dc.png)
![ws01 — secure channel confirmed](screenshots/topology-walkthrough/07-ws01.png)

---

## VLAN 20 — Detection / SOC Platform

**Splunk:** up and reachable.

**Security Onion:** a second SIEM/NSM platform added alongside Splunk — own Elastic stack, Zeek, and Suricata. Full build writeup: [`../security-onion/`](../security-onion/).

![Security Onion — confirmed live](screenshots/topology-walkthrough/08-security-onion.png)

**Wazuh:** dashboard up, agents reporting.

![Wazuh dashboard](screenshots/topology-walkthrough/09-wazuh.png)

**Zeek — found silently crashed 25 days earlier.** Log timestamps were stale; `zeekctl status` confirmed `crashed`. Fixed with `zeekctl deploy`, verified with fresh log timestamps immediately after.

![Zeek — fixed and logging current traffic](screenshots/topology-walkthrough/10-zeek-fixed.png)

**n8n:** the full SOAR pipeline (hash branch, network/spray branch, OPNsense auto-block, IRIS case creation) loaded correctly, published and intact.

![n8n — SOAR pipeline loaded](screenshots/topology-walkthrough/11-n8n.png)

**IRIS:** case management dashboard reachable.

![IRIS — case management](screenshots/topology-walkthrough/12-iris.png)

---

## VLAN 50 — ICSNETWORK (OT Purdue Level 0/1)

`grfics-sim`: process simulation live, in-simulation clock matching real time — confirms it's actively running, not a frozen screen.

![grfics-sim — live process view](screenshots/topology-walkthrough/13-grfics-sim.png)

`OpenPLC`: Modbus master connected to all 6 field devices (feed1, feed2, purge, product, tank, analyzer).

![OpenPLC — all 6 devices connected](screenshots/topology-walkthrough/14-openplc-a.png)

---

## VLAN 55 — OTDMZ (OT Purdue Level 2)

`ScadaBR`: HMI live view, real values (not placeholder `--`), no warning triangles — confirms the full Level 0→1→2 Modbus chain end to end.

![ScadaBR — live HMI](screenshots/topology-walkthrough/15-scadabr-a.png)

`node-red`: caught mid-execution with an active BACnet read in the debug panel — a live, successful bulk read of multiple HVAC devices (AHU-01, CO2-01, FCU-01, FCU-02, OAT-01), not just a static confirmation that the editor loads.

![node-red — live BACnet read captured](screenshots/topology-walkthrough/16-node-red.png)

---

## VLAN 60 — BACNET

All 7 simulated HVAC/BMS devices online: AHU-01, CO2-01, FCU-01, FCU-02, OAT-01, TSTAT-01, ZC-01.

![bacnet-sim — all 7 devices online](screenshots/topology-walkthrough/17-bacnet-sim.png)

