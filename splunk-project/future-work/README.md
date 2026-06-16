# Future Work

Content in this folder was written but **not validated against live attack traffic** in this lab. It's kept here, clearly separated from the validated work in [`credential-attack-detection/`](../credential-attack-detection/), so the portfolio doesn't overstate what's actually been demonstrated.

---

## OPNsense / Suricata Detections

| Detection | File | Data Source | MITRE ID | Status |
|---|---|---|---|---|
| Firewall Brute Force | [`opnsense-detections/firewall-brute-force.spl`](opnsense-detections/firewall-brute-force.spl) | `index=opnsense`, filterlog | T1110.001 | Written, untested |
| Firewall Password Spray | [`opnsense-detections/firewall-spray.spl`](opnsense-detections/firewall-spray.spl) | `index=opnsense`, filterlog | T1110.003 | Written, untested |
| Port Scan / Recon | [`opnsense-detections/port-scan.spl`](opnsense-detections/port-scan.spl) | `index=opnsense`, filterlog | T1046, T1595 | Written, untested |
| Suricata Alert Correlation | [`opnsense-detections/suricata-alerts.spl`](opnsense-detections/suricata-alerts.spl) | Suricata EVE JSON | Multiple | Written, untested |

The OPNsense firewall and Suricata IDS are both running and confirmed forwarding logs to `index=opnsense` (see [lab infrastructure](../lab-infrastructure/)), so these queries are ready to test — they just haven't been run against a live attack yet. Logical next step: re-run the Windows/Linux attacks from [`credential-attack-detection/`](../credential-attack-detection/) and check whether these fire on the same traffic at the network layer.

---

## Sample Data

[`sample-data/`](sample-data/) contains synthetic Windows Security Event and Linux auth.log entries for anyone reviewing this portfolio without a live Splunk instance to test against. These were not used to validate the detections in `credential-attack-detection/` — that validation used real attack traffic.

---

## Extended Attack Tool Reference

[`extended-attack-tool-reference.md`](extended-attack-tool-reference.md) documents additional attack techniques and tools (Kerberos spray via Kerbrute, multi-host spray via Medusa, two-phase username enumeration + targeted brute force) that weren't run in this lab but map to detection logic already covered by the existing SPL files. Useful as a reference for extending the lab later.
