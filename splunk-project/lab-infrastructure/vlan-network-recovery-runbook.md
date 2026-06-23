# VLAN Network Migration & Recovery Runbook
**Date:** 2026-06-22  
**Cluster:** homelab (pve1 + pve2)  
**Goal:** Migrate Proxmox cluster from flat 10.10.0.x to VLAN-segmented network with management on VLAN 40

---

## Final Network Design

### Switch (TL-SG108E) Port Assignments
| Port | Device | Role | VLAN Config |
|---|---|---|---|
| 1 | pve1 (enp2s0f1) | Lab trunk | Tagged 10/20/30/40, PVID=40 |
| 2 | pve2 (enp4s0f0) | Lab trunk | Tagged 10/20/30/40, PVID=40 |
| 3 | Desktop 1 | Management | Untagged VLAN 40, PVID=40 |
| 4 | Desktop 2 | Management | Untagged VLAN 40, PVID=40 |
| 8 | Home router | WAN uplink | Untagged VLAN 1, PVID=1 |

### Switch VLAN Table
| VLAN | Name | Member Ports | Tagged | Untagged |
|---|---|---|---|---|
| 1 | Default | 3-8 | — | 3-8 |
| 10 | SERVERS | 1-2 | 1-2 | — |
| 20 | DETECTION | 1-2 | 1-2 | — |
| 30 | ATTACKERS | 1-2 | 1-2 | — |
| 40 | MGMT | 1-4 | 1-2 | 3-4 |

### Management IPs
| Host | IP | Method |
|---|---|---|
| pve1 | 10.10.40.201 | DHCP reservation (OPNsense) |
| pve2 | 10.10.40.202 | DHCP reservation (OPNsense) |
| pve1 fallback | 192.168.1.201 | Direct cable to home router (always works) |

---

## What Broke and Why

After setting the switch VLAN config, pve1 and pve2 became unreachable because:
- Switch PVID=40 on ports 1-2 tags all untagged frames from pve1/pve2 as VLAN 40
- But pve1/pve2 management IPs were on 10.10.0.x (wrong subnet for VLAN 40)
- VLAN 40 egresses ports 1-2 as **tagged** — so incoming ARP replies arrive tagged, and the native bridge IP never receives them

---

## Step-by-Step Recovery

### Step 1 — Access pve1 via fallback
pve1's `enp2s0f0` is cabled **directly** to the home router (bypasses switch).  
Desktop on VLAN 40 → OPNsense routes to 192.168.1.x via WAN → pve1 reachable.

```
https://192.168.1.201:8006
```

### Step 2 — Fix pve1 network interface
From pve1 Proxmox UI → Shell:

```bash
nano /etc/network/interfaces
```

Add two blocks — `vmbr1` (bridge, no IP) and `vmbr1.40` (VLAN sub-interface with DHCP):

```
auto vmbr1
iface vmbr1 inet manual
        bridge-ports enp2s0f1
        bridge-stp off
        bridge-fd 0
        bridge-vlan-aware yes
        bridge-vids 2-4094
        post-up ip link set vmbr1 promisc on

auto vmbr1.40
iface vmbr1.40 inet dhcp
        vlan-raw-device vmbr1
```

**Key:** `vlan-raw-device vmbr1` is required — without it, ifupdown2 silently skips creating vmbr1.40 on boot.

```bash
ifreload -a
```

If ifreload errors, create the interface manually and test:
```bash
ip link add link vmbr1 name vmbr1.40 type vlan id 40
ip link set vmbr1.40 up
bridge vlan add dev vmbr1 vid 40 self
dhclient -v vmbr1.40
```

### Step 3 — Set DHCP reservation for pve1
In OPNsense → Services → DHCPv4 → MANAGEMENT → Leases, find pve1 and click `+`:
- MAC: from `ip link show vmbr1.40`
- IP: `10.10.40.201`

Renew lease:
```bash
dhclient -r vmbr1.40 && dhclient vmbr1.40
```

### Step 4 — Fix pve2 (physical console required)
pve2 has no fallback cable. Plug monitor + keyboard directly into pve2.

```bash
nano /etc/network/interfaces
```

Same two-block config as pve1, but `bridge-ports enp4s0f0`:

```
auto vmbr1
iface vmbr1 inet manual
        bridge-ports enp4s0f0
        bridge-stp off
        bridge-fd 0
        bridge-vlan-aware yes
        bridge-vids 2-4094
        post-up ip link set vmbr1 promisc on

auto vmbr1.40
iface vmbr1.40 inet dhcp
        vlan-raw-device vmbr1
```

If ifupdown2 errors, manually create the interface and get a DHCP lease:
```bash
ip link add link vmbr1 name vmbr1.40 type vlan id 40
ip link set vmbr1.40 up
bridge vlan add dev vmbr1 vid 40 self
dhclient -v vmbr1.40
```

Reboot to make persistent:
```bash
reboot
```

### Step 5 — Set DHCP reservation for pve2
In OPNsense → Services → DHCPv4 → MANAGEMENT → Reservations:
- pve2 MAC: `a0:10:a2:b8:eb:bb`
- IP: `10.10.40.202`

Renew on pve2:
```bash
dhclient -r vmbr1.40 && dhclient vmbr1.40
```

### Step 6 — Fix corosync
corosync had old ring0 IPs (10.10.0.201 / 10.10.0.200). Update on pve1:

```bash
cp /etc/pve/corosync.conf /tmp/corosync.conf
sed -i 's/ring0_addr: 10.10.0.201/ring0_addr: 10.10.40.201/' /tmp/corosync.conf
sed -i 's/ring0_addr: 10.10.0.200/ring0_addr: 10.10.40.202/' /tmp/corosync.conf
sed -i 's/config_version: [0-9]*/config_version: 5/' /tmp/corosync.conf
```

To write to /etc/pve/ (pmxcfs), corosync must be running. If corosync is down, write directly:
```bash
cp /tmp/corosync.conf /etc/corosync/corosync.conf
```

If pmxcfs has quorum, use:
```bash
pvecm expected 1   # grants quorum to pve1 alone → makes /etc/pve/ writable
cp /tmp/corosync.conf /etc/pve/corosync.conf
```

Copy to pve2:
```bash
scp /tmp/corosync.conf root@10.10.40.202:/etc/corosync/corosync.conf
```

### Step 7 — Fix corosync totem version mismatch
Both nodes had an older corosync binary that only supports `version: 2` in the totem block.  
Change on both nodes before starting corosync:

```bash
sed -i 's/version: 3/version: 2/' /etc/corosync/corosync.conf
```

Start corosync on pve1 first, then pve2:
```bash
systemctl start corosync
systemctl enable corosync
```

### Step 8 — Verify cluster
From pve1:
```bash
pvecm status
```

Expected output:
```
Quorate: Yes
Total votes: 2
Membership:
  10.10.40.201 (local)
  10.10.40.202
```

---

## Step 9 — Make vmbr1.40 static (critical)

vmbr1.40 must use a **static IP**, not DHCP. OPNsense is a VM on pve1 — it's not running during pve1's boot sequence, so DHCP will fail. corosync tries to bind to ring0_addr on boot and will fail if the interface has no IP yet.

Edit `/etc/network/interfaces` on **pve1**:
```
auto vmbr1.40
iface vmbr1.40 inet static
        address 10.10.40.201/24
        gateway 10.10.40.1
        vlan-raw-device vmbr1
```

Edit on **pve2**:
```
auto vmbr1.40
iface vmbr1.40 inet static
        address 10.10.40.202/24
        gateway 10.10.40.1
        vlan-raw-device vmbr1
```

DHCP on Linux assigns /32 host routes — this breaks subnet routing. Static /24 is correct.

### Step 10 — Reboot sequence

Reboot pve1 first. If pve2 isn't up when corosync starts, pve1 won't have quorum. Fix:
```bash
pvecm expected 1
```

This grants single-node quorum until pve2 rejoins. Do NOT run this if pve2 is already in the cluster — it would split the quorum.

---

## Gotchas Learned

| Issue | Root Cause | Fix |
|---|---|---|
| vmbr1.40 not created on boot | ifupdown2 needs `vlan-raw-device vmbr1` | Add directive to iface block |
| pve2 unreachable, no fallback | No direct cable to home router | Physical console only |
| /etc/pve/ Permission denied | pmxcfs read-only when no corosync quorum | Write to /etc/corosync/ directly, or use `pvecm expected 1` |
| corosync exit status 8 | totem `version: 3` not supported by installed binary | Change to `version: 2` on both nodes |
| config_version rollback | pmxcfs propagated old version from pve2 | Bump config_version higher than any node has seen (use 5+) |
| VLAN 40 tagged frames miss host IP | VLAN-aware bridge delivers tagged frames to VMs, not host native IP | Use vmbr1.40 sub-interface, not IP on vmbr1 directly |
| pvecm updatecerts resets corosync.conf to version: 3 | updatecerts copies cluster's /etc/pve/corosync.conf over /etc/corosync/corosync.conf | Re-run `sed -i 's/version: 3/version: 2/' /etc/corosync/corosync.conf` after every cert update |
| Cross-node shell: "ssh: connect to host 10.10.0.x port 22" | pveproxy uses /etc/hosts to resolve node names for SSH | Update /etc/hosts on both nodes: `10.10.40.201 pve1.home pve1` and `10.10.40.202 pve2.home pve2` |
| Proxmox web UI Network → Apply Configuration overwrites /etc/network/interfaces | Proxmox has its own network DB in pmxcfs — Apply writes that DB to disk | Never use Apply Configuration after manual edits to /etc/network/interfaces; edit the file directly and run `ifreload -a` |
| vmbr1.40 DHCP gets /32 instead of /24 | Linux DHCP client behavior for some leases | Use static IP — change `inet dhcp` to `inet static` with explicit /24 |
| pvedaemon restart hangs | Open connections prevent graceful shutdown | `systemctl kill --signal=SIGKILL pvedaemon` then `systemctl start pvedaemon` |
| Cross-node shell still broken after all config fixes | Stuck pvedaemon from failed restart | Reboot the node — clean boot fixes stuck services |
| No quorum after single-node reboot | pve2 not yet up when corosync starts on pve1 | `pvecm expected 1` on pve1 to grant temporary quorum |

---

## pveproxy Cross-Node Shell — How It Works

When you open pve2's Shell from pve1's web UI, pve1's pveproxy SSHes to pve2 using:
```bash
/usr/bin/ssh -e none -o BatchMode=yes \
  -o HostKeyAlias=<node> \
  -o UserKnownHostsFile=/etc/pve/nodes/<node>/ssh_known_hosts \
  -o GlobalKnownHostsFile=none \
  root@<IP from PVE::Cluster::remote_node_ip>
```

The IP comes from `PVE::Cluster::remote_node_ip()` which reads corosync ring0_addr. Test it:
```bash
perl -MPVE::Cluster -e 'print PVE::Cluster::remote_node_ip("pve2")."\n"'
```

If corosync has wrong IPs → fix corosync.conf  
If corosync is right but shell fails → check /etc/pve/nodes/<node>/ssh_known_hosts has valid key  
If SSH command works manually but shell fails → reboot (stuck pvedaemon)

---

## Pending
- [ ] Upgrade corosync on both nodes (`apt upgrade corosync`) to restore `version: 3`
- [ ] Update /etc/pve/corosync.conf with version: 3 after upgrade
- [ ] Start pve2 VMs (208 win-dc, 209 wazuh, 210 ubuntu)
