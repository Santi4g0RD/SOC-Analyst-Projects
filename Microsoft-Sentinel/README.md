# Microsoft Sentinel — Attack Map Workbooks

**Author:** Santiago Abel Ruiz Diaz
**LinkedIn:** [santiago-a-ruiz-diaz-4aa418b2](https://www.linkedin.com/in/santiago-a-ruiz-diaz-4aa418b2/)
**GitHub:** [Santi4g0RD](https://github.com/Santi4g0RD)
**Platform:** Microsoft Azure — Microsoft Sentinel (SIEM)
**Workspace:** law-cyber-range
**Date:** 2026-06-06

---

## Overview

Built five geographic attack map workbooks in Microsoft Sentinel to visualize real-time security events against a live Azure cyber range environment. Each workbook uses a KQL query enriched with a GeoIP watchlist to map source IPs to latitude/longitude coordinates, rendering a heatmap of attack activity by volume and origin.

The environment was actively receiving inbound traffic from external threat actors during the lab — the maps show real attack data, not simulated events.

| # | Map | Data Source | Detects |
|---|-----|-------------|---------|
| 1 | Allowed Inbound Malicious Flows | `AzureNetworkAnalytics_CL` | NSG-flagged malicious traffic allowed into the network |
| 2 | VM Authentication Failures | `DeviceLogonEvents` | Brute-force attempts against VMs by source IP |
| 3 | Entra ID Login Failures | `SigninLogs` | Azure AD failed logins by identity and location |
| 4 | Entra ID Login Successes | `SigninLogs` | Successful authentications — baseline and anomaly detection |
| 5 | Azure Resource Creation | `AzureActivity` | Who created Azure resources and from where |

---

## Data Ingestion

Before building the maps, the workspace was confirmed to be ingesting data at scale across all relevant log sources.

**[Log Volume Overview](./screenshots/sentinel-log-volume-overview.png):** `AzureNetworkAnalyticsIP_CL` — 469M events | `AzureNetworkAnalytics_CL` — 70.2M | `DeviceProcessEvents` — 20.8M | `AzureActivity` — 18.8M | `DeviceNetworkEvents` — 18.1M

---

## Workbook Creation

Workbooks were built from scratch in Sentinel → Threat Management → Workbooks → Add a Workbook. Each map tile was added using the Advanced Editor to paste the KQL JSON directly.

**[Sentinel Workbooks Portal](./screenshots/sentinel-workbooks-portal.png):** Entry point for creating and managing workbooks.

**[Add Query](./screenshots/sentinel-workbook-add-query.png):** Each map is a query tile added to the workbook canvas.

**[Advanced Editor — JSON](./screenshots/sentinel-workbook-json-editor.png):** KQL query and map visualization settings pasted directly as JSON. This is how the query files in `Map-Creation/` are used.

---

## Attack Maps

### Malicious Traffic Entering the Network

**[Full Map View](./screenshots/sentinel-malicious-traffic-map.png):** Live view of the completed Malicious Traffic workbook showing inbound malicious flows geo-mapped by source IP.

**[Allowed Inbound Malicious Flows — Detailed](./screenshots/sentinel-allowed-inbound-malicious-flows.png):** Heatmap showing malicious inbound flows allowed through the NSG. Top sources during the observation window:

| Location | Flows |
|----------|-------|
| Muncie, United States | 856 |
| San Francisco, United States | 854 |
| Guayaquil, Ecuador | 530 |
| Calgary, Canada | 384 |
| United States (other) | 324 |
| Oxford, United Kingdom | 288 |
| São Paulo, Brazil | 203 |

---

## KQL Approach

Each query follows the same pattern:

1. Pull the GeoIP enrichment watchlist: `let GeoIPDB_FULL = _GetWatchlist("geoip")`
2. Query the relevant log table and filter for the event of interest
3. Join source IPs to GeoIP using `evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)`
4. Project latitude, longitude, and a friendly label for the map renderer

**Example — Allowed Inbound Malicious Flows:**

```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
let MaliciousFlows = AzureNetworkAnalytics_CL
| where FlowType_s == "MaliciousFlow"
| order by TimeGenerated desc
| project TimeGenerated, FlowType = FlowType_s, IpAddress = SrcIP_s,
          DestinationIpAddress = DestIP_s, DestinationPort = DestPort_d,
          Protocol = L7Protocol_s, NSGRuleMatched = NSGRules_s;
MaliciousFlows
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| project TimeGenerated, FlowType, IpAddress, DestinationIpAddress,
          DestinationPort, Protocol, NSGRuleMatched,
          latitude, longitude,
          city = cityname, country = countryname,
          friendly_location = strcat(cityname, " (", countryname, ")")
```

---

## Map Query Files

| File | Visualization |
|------|--------------|
| [Allowed-Inbound-Malicious-Flows.json](./Map-Creation/Allowed-Inbound-Malicious-Flows.json) | Malicious flows by source IP via `AzureNetworkAnalytics_CL` |
| [VM-Authentication-Failures.json](./Map-Creation/VM-Authentication-Failures.json) | Failed VM logons via `DeviceLogonEvents` |
| [Login-Failure-Directory.json](./Map-Creation/Login-Failure-Directory.json) | Entra ID failed sign-ins via `SigninLogs` |
| [Login-Success-Directory.json](./Map-Creation/Login-Success-Directory.json) | Entra ID successful sign-ins via `SigninLogs` |
| [Azure-Resource-Creation.json](./Map-Creation/Azure-Resource-Creation.json) | Resource creation events via `AzureActivity` |
| [Azure-Resource-Creation-v2.json](./Map-Creation/Azure-Resource-Creation-v2.json) | Resource creation v2 — filters service principal callers, regex-validates IPv4 |

---

## Related Projects

- [DISA STIG: Windows Server 2025 Hardening](../Win25%20Server%20STIG%20Project/)
- [DISA STIG: Windows 11 Hardening](../Win11%20STIG%20Project/)
- [DISA STIG: Ubuntu Server 24.04 Hardening](../Ubuntu%20Server%20STIG%20Project/)
