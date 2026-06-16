# Splunk Home Lab — Detection Engineering

**Analyst:** Santiago Abel Ruiz Diaz

A self-hosted Proxmox lab built to practice detection engineering end-to-end: stand up the infrastructure, simulate real attacks, and validate that the SIEM actually catches them.

---

## How this lab came together

### Step 1 — Build the infrastructure
Proxmox host running OPNsense (firewall + Suricata IDS) to segment an attacker VLAN from a target LAN, plus Splunk Enterprise collecting logs from every target.
→ [`lab-infrastructure/`](lab-infrastructure/) · [proof](lab-infrastructure/screenshots/opnsense-syslog-confirmed.png)

### Step 2 — Simulate a Windows credential attack
NetExec brute force and password spray over SMB against a Windows Server 2025 target. Both detections fired: 31 failed logons, 6 unique accounts targeted.
→ [`credential-attack-detection/`](credential-attack-detection/) (Windows section) · [proof](credential-attack-detection/screenshots/windows-brute-force-detected.png)

### Step 3 — Simulate a Linux credential attack
Hydra brute force and password spray over SSH against a Kali Purple target. Both detections fired: 21 failed logons, 6 unique accounts targeted — and bucket window size turned out to matter for telling the two attacks apart.
→ [`credential-attack-detection/`](credential-attack-detection/) (Linux section) · [proof](credential-attack-detection/screenshots/linux-brute-force-detected.png)

### Step 4 — What's next
Firewall/IDS-layer detections written against the OPNsense + Suricata setup, not yet run against live traffic. Logical next step: replay the Windows/Linux attacks and see if they fire at the network layer too.
→ [`future-work/`](future-work/)

---

## Projects

| Project | What it covers |
|---|---|
| [`lab-infrastructure/`](lab-infrastructure/) | The platform — Proxmox VMs, OPNsense firewall + Suricata IDS, network segmentation, Splunk Enterprise deployment |
| [`credential-attack-detection/`](credential-attack-detection/) | The deliverable — Windows (NetExec/SMB) and Linux (Hydra/SSH) brute force + password spray attacks, with validated SPL detections |
| [`future-work/`](future-work/) | Written-but-untested firewall/IDS detections and extended attack reference material |
