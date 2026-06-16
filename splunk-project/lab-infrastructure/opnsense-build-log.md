# OPNsense Build Log
## Console + GUI Walkthrough (Proxmox Home Lab)

**Analyst:** Santiago Abel Ruiz Diaz
**Proxmox Host:** pve1 — Intel i5-4570 @ 3.20GHz, 4 cores, 31.24 GiB RAM, 3.57 TiB HDD
**OPNsense Version:** 26.1.6_2 (amd64)
**Status:** Complete

This is the raw click-by-click build log for OPNsense specifically. For the final network diagram, VM inventory, and the Splunk/Windows/Linux build steps, see the [lab infrastructure README](README.md) one level up. Final VM ID for OPNsense is **201** (assigned 205 during initial planning, renumbered before final build).

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

**VM 201 → Hardware → Add → Network Device**

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
**VM 201 → Hardware → CD/DVD Drive → Edit → Do not use any media**

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

## Phase 1 — OPNsense Web GUI Configuration (COMPLETED)

- System → Settings → General → Timezone, DNS (8.8.8.8 / 8.8.4.4), Prefer IPv4
- Interfaces → OPT1 → Enable → IPv4: 192.168.20.1/24 (DHCP pool configured but unused — see note below)
- Firewall rules: OPT1 → allow TCP from 192.168.20.0/24 to 192.168.10.0/24 on ports 22, 445, 3389; block all other OPT1 traffic (logged); LAN → allow all outbound (default)
- Suricata IDS enabled on LAN + OPT1 with ET Open ruleset
- Syslog → Splunk: UDP target added to 192.168.10.50:514

**Note:** OPT1 DHCP never worked reliably (Kea quirk) — the Kali attacker VM (192.168.20.100) was given a static IP instead.

For the rest of the build (Splunk, Windows target, Kali Purple, attack simulation), see the [lab infrastructure README](README.md).
