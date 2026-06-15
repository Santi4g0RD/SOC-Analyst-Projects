# OPNsense Firewall Setup Guide
## Proxmox Home Lab — Credential Attack Detection Lab

**Analyst:** Santiago Abel Ruiz Diaz
**Proxmox Host:** pve1 — Intel i5-4570 @ 3.20GHz, 4 cores, 31.24 GiB RAM, 3.57 TiB HDD
**OPNsense Version:** 26.1.6_2 (amd64)
**Status:** In progress

---

## Lab Topology

```
                        ┌─────────────────────────────────────────────────────┐
                        │              Proxmox Host (pve1)                    │
                        │                                                     │
                        │  ┌──────────────────────────────────────────────┐  │
                        │  │  Linux Bridges                               │  │
                        │  │  vmbr0 — 192.168.1.201/24  (WAN/Management) │  │
                        │  │  vmbr1 — (no IP)           (Lab LAN)        │  │
                        │  │  vmbr2 — (no IP)           (Lab Attacker)   │  │
                        │  └──────────────────────────────────────────────┘  │
                        │                                                     │
                        │  ┌─────────────┐   ┌──────────┐  ┌─────────────┐  │
                        │  │ VM 205      │   │ VM 20X   │  │ VM 20X      │  │
                        │  │ OPNsense    │   │ Windows  │  │ Splunk      │  │
                        │  │ vtnet0=vmbr0│   │ Server   │  │ (Ubuntu)    │  │
                        │  │ vtnet1=vmbr1│   │ vmbr1    │  │ vmbr1       │  │
                        │  │ vtnet2=vmbr2│   └──────────┘  └─────────────┘  │
                        │  └─────────────┘                                   │
                        │                                                     │
                        │  ┌──────────────────┐   ┌────────────────────────┐ │
                        │  │ VM 202           │   │ VM 203                 │ │
                        │  │ Kali (voldemort) │   │ Kali Purple            │ │
                        │  │ vmbr2 (attacker) │   │ (purple-voldemort)     │ │
                        │  └──────────────────┘   │ vmbr1 (temp - browser) │ │
                        │                         └────────────────────────┘ │
                        └─────────────────────────────────────────────────────┘

Interface assignments inside OPNsense:
  WAN  → vtnet0 → vmbr0 → 192.168.1.138/24 (DHCP from home router)
  LAN  → vtnet1 → vmbr1 → 192.168.10.1/24  (Lab targets + Splunk)
  OPT1 → vtnet2 → vmbr2 → 192.168.20.1/24  (Kali attacker VLAN)
```

---

## VM Allocation

| VM ID | Name | Role | Bridge | RAM | vCPU | Disk |
|---|---|---|---|---|---|---|
| 205 | opnsense | Firewall / IDS | vmbr0+1+2 | 2 GB | 1 | 32 GB |
| TBD | splunk | SIEM (Ubuntu 26.04) | vmbr1 | 8 GB | 2 | 200 GB |
| TBD | win-target | Windows Server 2022 | vmbr1 | 6 GB | 2 | 80 GB |
| 202 | voldemort | Kali (attacker) | vmbr2 | 4 GB | 2 | — |
| 203 | purple-voldemort | Kali Purple (Linux target) | vmbr1 | 4 GB | 2 | — |
| 204 | REMnux | Malware analysis (separate) | — | — | — | — |

---

## Phase 1 — OPNsense Installation (COMPLETED)

### Step 1 — Create Proxmox Network Bridges

**pve1 → System → Network → Create → Linux Bridge**

Created two bridges:

| Name | IP | Bridge ports | Comment |
|---|---|---|---|
| vmbr1 | (none) | (none) | Lab LAN |
| vmbr2 | (none) | (none) | Lab Attacker |

Clicked **Apply Configuration** to activate both.

---

### Step 2 — Create OPNsense VM

**Proxmox → Create VM**

| Tab | Setting | Value |
|---|---|---|
| General | VM ID | 205 |
| General | Name | opnsense |
| OS | ISO | OPNsense-26.1.6-dvd-amd64.iso |
| OS | Type | Other |
| System | BIOS | OVMF (UEFI) |
| System | Add EFI Disk | Checked — local storage |
| System | Pre-Enroll keys | **UNCHECKED** (OPNsense does not support Secure Boot) |
| System | SCSI Controller | VirtIO SCSI |
| System | Qemu Agent | Checked |
| Disks | Bus | VirtIO Block |
| Disks | Size | 32 GB |
| CPU | Cores | 1 |
| CPU | Type | host |
| Memory | RAM | 2048 MB |
| Network | Bridge | vmbr0 (WAN) |
| Network | Model | VirtIO (paravirtualized) |
| Network | Firewall | Unchecked |
| Confirm | Start after created | Unchecked |

---

### Step 3 — Add LAN and OPT1 NICs

Before booting, added two more network devices:

**VM 205 → Hardware → Add → Network Device**

| NIC | Bridge | Model | Firewall |
|---|---|---|---|
| net1 | vmbr1 | VirtIO (paravirt) | Unchecked |
| net2 | vmbr2 | VirtIO (paravirt) | Unchecked |

Result in Hardware:
```
net0 → vmbr0  (WAN)
net1 → vmbr1  (LAN)
net2 → vmbr2  (OPT1 - Kali VLAN)
```

---

### Step 4 — Install OPNsense

Started VM and opened console. Installation steps:

```
Login:     installer
Password:  opnsense

Keymap:    Default (Enter)
Install:   Install (UFS)
Disk:      vtbd0 (32GB) → OK
Password:  Set root password
Complete:  Complete Install → reboot
```

After reboot, removed ISO from VM:
**VM 205 → Hardware → CD/DVD Drive → Edit → Do not use any media**

---

### Step 5 — Assign Interfaces

From OPNsense console menu → option **1 (Assign interfaces)**:

```
LAGGs:   n
VLANs:   n

Detected NICs:
  vtnet0   bc:24:11:af:f7:4d   VirtIO
  vtnet1   bc:24:11:f1:5c:32   VirtIO
  vtnet2   bc:24:11:d0:60:3a   VirtIO

WAN:   vtnet0
LAN:   vtnet1
OPT1:  vtnet2

Proceed: y
```

---

### Step 6 — Set LAN IP Address

From console menu → option **2 (Set interface IP address)** → interface **1 (LAN)**:

```
DHCP:              n
IPv4 address:      192.168.10.1
Subnet bit count:  24
Gateway:           (Enter — none for LAN)
IPv6 WAN track:    n
IPv6 DHCP:         n
IPv6 address:      (Enter — none)
Enable DHCP:       y
DHCP start:        192.168.10.100
DHCP end:          192.168.10.200
Revert to HTTP:    n
New certificate:   y
Restore GUI defaults: n
```

Console confirmed:
```
LAN  (vtnet1) → 192.168.10.1/24
OPT1 (vtnet2) → (no IP yet)
WAN  (vtnet0) → 192.168.1.138/24  (DHCP)

Web GUI: https://192.168.10.1
```

---

### Step 7 — Access Web GUI

Moved VM 203 (Kali Purple) to vmbr1 temporarily for browser access.

Opened browser in Kali Purple → `https://192.168.10.1`

Login:
```
Username: root
Password: (set during install)
```

---

## Phase 1 — OPNsense Web GUI Configuration (IN PROGRESS)

### ✅ Done
- System → Settings → General → Timezone, DNS (8.8.8.8 / 8.8.4.4), Prefer IPv4

### ⬜ Remaining

**1. Set OPT1 IP (Kali attacker VLAN)**
- Interfaces → OPT1 → Enable → IPv4: 192.168.20.1/24
- Enable DHCP for OPT1: 192.168.20.100–192.168.20.200

**2. Firewall rules**
- OPT1 → allow TCP from 192.168.20.0/24 to 192.168.10.0/24 on ports 22, 445, 3389
- OPT1 → block all other traffic (logged)
- LAN → allow all outbound (default)

**3. Suricata IDS**
- Services → Intrusion Detection → Enable
- Interfaces: LAN + OPT1
- Download ET Open ruleset

**4. Syslog → Splunk**
- System → Logging / Targets → Add
- UDP → 192.168.10.50 (Splunk LAN IP) → port 514

---

## Phase 2 — Splunk on Ubuntu (PENDING)

## Phase 3 — Windows Server 2022 Target (PENDING)

## Phase 4 — Move Kali to vmbr2 / Kali Purple to vmbr1 (PENDING)

## Phase 5 — Attack Simulation + Detection Validation (PENDING)
