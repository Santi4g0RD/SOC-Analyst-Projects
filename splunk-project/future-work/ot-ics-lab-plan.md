# OT/ICS Attack Detection Lab — Planned

**Status:** Planned, not yet built. Captured here ahead of the build so the design and its reasoning aren't lost — see [`future-work/README.md`](README.md) for how this folder is used.

Extends the existing VLAN-segmented lab (see [`ad-privesc-lab/`](../ad-privesc-lab/)) with an OT/ICS segment to build Modbus/SCADA detection capability alongside the existing AD/Windows/Linux coverage: [GRFICSv2](https://github.com/Fortiphyd/GRFICSv2) (chemical process simulation + OpenPLC + ScadaBR HMI) on a new VLAN, monitored by the existing Zeek/Suricata/Splunk stack, with SOAR response via n8n + IRIS.

---

## Topology

```
VLAN 50 — OT / Process — 10.10.50.0/24 — GW 10.10.50.1 on OPNsense

  ScadaBR HMI        10.10.50.30   pve1   (legitimate Modbus master)
  OpenPLC (plc_2)    10.10.50.20   pve2
  ChemicalPlant sim  10.10.50.10   pve2
```

Optional follow-on: **VLAN 55 — OT DMZ — 10.10.55.0/24** (Purdue Level 3.5) for a later segmentation exercise — firewall rules restricting IT (VLAN 10) to DMZ-only and DMZ to OT-only, no direct IT→OT path.

---

## Why not the stock 5-VM GRFICS stack

GRFICSv2 ships as 5 VMs: simulation, PLC, HMI, pfSense, and Kali. This lab already has OPNsense doing inter-VLAN routing and `voldemort` (VLAN 30) as the attacker box, so the bundled pfSense and Kali VMs are redundant. Dropping them cuts the footprint from the ~16GB documented for the full 5-VM stack down to roughly 7-8GB for the 3 VMs that are actually unique to GRFICS.

| VM | Est. RAM | Est. vCPU | Host |
|---|---|---|---|
| ScadaBR HMI | ~2 GB | 1 | pve1 |
| OpenPLC | ~1-2 GB | 1 | pve2 |
| ChemicalPlant simulation | ~4 GB | 2 | pve2 |

Total ~7-8 GB against 12 GB free on each of pve1/pve2. Estimates only — not vendor-documented — to be confirmed against each VM's `.ovf` descriptor before deploying.

---

## Why split across pve1 and pve2

The AD privesc lab already demonstrated that Zeek (on hardware SPAN) is blind to traffic between VMs on the same Proxmox host — it never crosses the physical switch (see the same-node blind spots noted throughout [`ad-privesc-lab/README.md`](../ad-privesc-lab/README.md), e.g. RDP lateral movement and obfuscated PowerShell C2). Putting the HMI on pve1 and the PLC/simulation on pve2 guarantees both the legitimate HMI→PLC baseline traffic and any attacker→PLC traffic physically cross the mirrored switch ports, preserving Zeek visibility for the whole exercise instead of only catching half of it.

---

## Planned detection stack integration

- **Zeek:** install the INL ICSNPP Modbus parser (`icsnpp-modbus`) → new `modbus.log` (function codes, register reads/writes) → `idx=ot`
- **Suricata (OPNsense):** enable the ET SCADA ruleset at the VLAN 50 boundary
- **Baseline:** capture a clean PCAP of GRFICS running normally before any attack traffic. ScadaBR HMI is the only legitimate Modbus master — any other source writing coils/registers is the anomaly signal
- **n8n SOAR:** trigger on a Modbus write from a source that isn't the HMI → alert + IRIS case. Deliberately **alert-only / human-in-the-loop**, not auto-block — OT prioritizes availability and safety over automated containment, a contrast worth documenting against this lab's IT auto-block branch

---

## Planned exercise

From `voldemort` (VLAN 30), pivot across the OPNsense boundary into VLAN 50 and write a false setpoint to the PLC:

- Recon: `nmap --script modbus-discover`, PLCScan
- Manipulate: `pymodbus`, `mbtget`, or `msf > auxiliary/scanner/scada/modbusclient`
- Validate the full chain: Suricata (boundary) → Zeek `modbus.log` → Splunk `idx=ot` → n8n → IRIS case

---

## Open items before build starts

- n8n and IRIS are already running in this lab (used for other detections) but not yet documented/committed to this repo — that catch-up is a prerequisite for the SOAR piece here
- WireGuard access into the home network is a separate pending task, useful for managing this build remotely
