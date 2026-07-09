# n8n SOAR Pipeline — Build Guide

**Goal:** Replace Shuffle with n8n as the SOAR platform. Build a complete Wazuh → SOAR pipeline with hash reputation (VirusTotal), alerting (Telegram + Email), and case management (DFIR-IRIS).

**Lab date:** 2026-07-08  
**n8n VM:** 10.10.20.80 (pve2, 2 GB RAM, Ubuntu 24.04)  
**IRIS VM:** 10.10.20.60  
**Wazuh manager:** 10.10.20.20  

---

## Part 1 — Provision the n8n VM

### 1.1 Clone from Ubuntu server template in Proxmox

- In Proxmox UI: right-click the Ubuntu template → Clone → Full clone
- Name it `n8n`, assign to pve2, give it 2 GB RAM and 20 GB disk
- Start the VM, open the console

### 1.2 Fix hostname

```bash
sudo hostnamectl set-hostname n8n
sudo sed -i 's/ubuntu-server/n8n/g' /etc/hosts
```

### 1.3 Fix netplan (cloned VMs have wrong MAC in config)

The cloned VM gets a new MAC address but netplan still has the old one. This causes "Cannot find unique matching interface" on boot.

```bash
ip link show   # note the actual MAC on ens18
sudo nano /etc/netplan/00-installer-config.yaml
```

Remove the `match:` and `set-name:` blocks entirely. Final config:

```yaml
network:
  version: 2
  ethernets:
    ens18:
      addresses:
        - 10.10.20.80/24
      dhcp6: false
      nameservers:
        addresses: [10.10.20.1, 8.8.8.8]
        search: []
      routes:
        - to: default
          via: 10.10.20.1
```

```bash
sudo netplan apply
```

### 1.4 Regenerate SSH host keys

Cloned VMs share SSH host keys with the template. Regenerate them:

```bash
sudo rm /etc/ssh/ssh_host_*
sudo ssh-keygen -A
sudo systemctl restart ssh
```

### 1.5 Install Node.js 20 and n8n

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs
sudo npm install -g n8n --unsafe-perm
```

### 1.6 Generate self-signed SSL certificate

n8n requires HTTPS for secure cookies. Generate a self-signed cert:

```bash
mkdir -p ~/.n8n/certs
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout ~/.n8n/certs/n8n.key \
  -out ~/.n8n/certs/n8n.crt \
  -subj "/CN=10.10.20.80"
```

### 1.7 Create systemd service

So n8n survives reboots and SSH disconnects:

```bash
sudo nano /etc/systemd/system/n8n.service
```

```ini
[Unit]
Description=n8n workflow automation
After=network.target

[Service]
Type=simple
User=abel
Environment=N8N_PROTOCOL=https
Environment=N8N_SSL_CERT=/home/abel/.n8n/certs/n8n.crt
Environment=N8N_SSL_KEY=/home/abel/.n8n/certs/n8n.key
Environment=WEBHOOK_URL=https://10.10.20.80:5678/
Environment=N8N_SECURE_COOKIE=true
ExecStart=/usr/bin/n8n start
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable n8n
sudo systemctl start n8n
sudo systemctl status n8n
```

Access n8n at `https://10.10.20.80:5678` and create the owner account.

---

## Part 2 — Update Wazuh to send alerts to n8n

SSH into the Wazuh manager and update the integration URL:

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Find the `<integration>` block and update:

```xml
<!-- Shuffle SOAR integration — main alert pipeline -->
<integration>
  <name>shuffle</name>
  <hook_url>https://10.10.20.80:5678/webhook/wazuh-alerts</hook_url>
  <rule_id>60204,100010,100011,100012,100020,100021,100022,100024,100025,100027,100030,100031</rule_id>
  <alert_format>json</alert_format>
</integration>
```

> **Note:** The integration name stays `shuffle` because it uses the existing `/var/ossec/integrations/shuffle.py` script which already has `verify=False` patched for self-signed certs.

```bash
sudo systemctl restart wazuh-manager
```

---

## Part 3 — Build the hash pipeline in n8n

### 3.1 Webhook trigger node

- Search: **Webhook**
- HTTP Method: POST
- Path: `wazuh-alerts`
- Respond: **Immediately** (Wazuh needs a fast 200 OK)
- Authentication: None

Production URL: `https://10.10.20.80:5678/webhook/wazuh-alerts`

**Test:** Click "Listen for test event", run mimikatz on ws01, confirm payload arrives.  
**Then pin the data** so all downstream nodes can be tested without re-triggering Wazuh.

### 3.2 Key Wazuh payload field paths (n8n)

Wazuh's shuffle integration wraps data under `all_fields`. Always drag-drop from the Schema view to confirm paths.

| Field | Path |
|---|---|
| SHA256 hashes string | `$json.body.all_fields.data.win.eventdata.hashes` |
| Agent name | `$json.body.all_fields.agent.name` |
| Agent IP | `$json.body.all_fields.agent.ip` |
| Rule ID | `$json.body.rule_id` |
| Rule description | `$json.body.all_fields.rule.description` |
| Timestamp | `$json.body.all_fields.timestamp` |
| MITRE ID | `$json.body.all_fields.rule.mitre.id[0]` |
| Source IP (spray) | `$json.body.all_fields.data.win.eventdata.ipAddress` |

### 3.3 IF node — branch on hash vs network alert

- Add **If** node after webhook
- Condition: drag `hashes` field → **Contains** → `SHA256`
- **True** output → hash pipeline
- **False** output → network/spray pipeline (built later)

### 3.4 Code node — extract SHA256 and bundle fields

- Add **Code** node on the true branch
- Language: JavaScript
- Mode: Run Once for All Items

```javascript
const hashes = $input.item.json.body.all_fields.data.win.eventdata.hashes;
const match = hashes.match(/SHA256=([A-Fa-f0-9]{64})/);
const sha256 = match ? match[1] : null;

return {
  sha256: sha256,
  agent_name: $input.first().json.body.all_fields.agent.name,
  agent_ip: $input.first().json.body.all_fields.agent.ip,
  rule_id: $input.first().json.body.rule_id,
  rule_description: $input.first().json.body.all_fields.rule.description,
  timestamp: $input.first().json.body.all_fields.timestamp
};
```

> **Tip:** Drag fields from the Schema view into the code editor to auto-fill the exact path.

### 3.5 VirusTotal HTTP Request node

- Add **HTTP Request** node after Code
- Method: GET
- URL: `https://www.virustotal.com/api/v3/files/{{ $json.sha256 }}`
- Credential for VirusTotal: **None** (native credential type conflicts with full URLs)
- Send Headers: on
  - `x-apikey`: your VT API key
- Settings tab → Ignore SSL Issues: off (VT uses valid cert)

Key output field: `$json.data.attributes.last_analysis_stats.malicious`

### 3.6 Telegram node

- Add **Telegram** node after VirusTotal
- Credential: add bot token
- Operation: Send Message
- Chat ID: your chat ID (get with `curl -s "https://api.telegram.org/bot<TOKEN>/getUpdates"`)
- Text:

```
🚨 MALICIOUS HASH DETECTED

Host: {{ $('Code').item.json.agent_name }}
Host IP: {{ $('Code').item.json.agent_ip }}
Time: {{ $('Code').item.json.timestamp }}

Rule:{{ $('Code').item.json.rule_description }}
SHA256:{{ $('Code').item.json.sha256 }}
VT Malicious: {{ $json.data.attributes.last_analysis_stats.malicious }} malicious
```

- Settings tab: disable **Append n8n attribution**

### 3.7 Email node (SMTP)

- Add **Send Email** node after VirusTotal (parallel to Telegram)
- Credential: SMTP account
  - User: `abel.soclabalerts@gmail.com`
  - Password: Gmail app password
  - Host: `smtp.gmail.com`
  - Port: 465
  - SSL/TLS: on
- From: `abel.soclabalerts@gmail.com`
- To: your personal email
- Subject: `🚨 MALICIOUS HASH - {{ $('Code').item.json.agent_name }}`
- Body:

```
MALICIOUS HASH DETECTED

Host: {{ $('Code').item.json.agent_name }}
Host IP: {{ $('Code').item.json.agent_ip }}
Time: {{ $('Code').item.json.timestamp }}

Rule: {{ $('Code').item.json.rule_description }}

SHA256: {{ $('Code').item.json.sha256 }}
VT Malicious Engines: {{ $('VirusTotal HTTP Request').item.json.data.attributes.last_analysis_stats.malicious }} malicious
VT Report: https://www.virustotal.com/gui/file/{{ $('Code').item.json.sha256 }}

IRIS Case: check IRIS dashboard for case details.
```

### 3.8 Fix expired IRIS SSL certificate

Before building IRIS nodes, the IRIS self-signed cert will likely be expired. Regenerate it:

```bash
# On the IRIS VM (10.10.20.60)
# Find where the cert is mounted
sudo docker inspect iriswebapp_nginx | grep -A2 "www/certs"
# Returns: /home/abel/iris-web/certificates/web_certificates:/www/certs

sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /home/abel/iris-web/certificates/web_certificates/iris_dev_key.pem \
  -out /home/abel/iris-web/certificates/web_certificates/iris_dev_cert.pem \
  -subj "/CN=10.10.20.60"

sudo docker restart iriswebapp_nginx
```

Also enable **Ignore SSL Issues** in the DFIR-IRIS credential in n8n.

### 3.9 IRIS Create Case node

- Add **HTTP Request** node after VirusTotal (parallel to Telegram and Email)
- Name it: `IRIS Add case`
- Method: POST
- URL: `https://10.10.20.60/manage/cases/add`
- Credential for DFIR-IRIS: **DFIR-IRIS account**
  - Base URL: `https://10.10.20.60`
  - API Key: SOAR service account API key (from IRIS → Advanced → Users → soar → Info)
  - Ignore SSL Issues: **on**
- Send Body: on → Body Content Type: JSON → Specify Body: **Using JSON**
- JSON body (switch field to Expression mode with the `fx` toggle):

```javascript
({
  "case_name": "MALICIOUS HASH - " + $('Code').item.json.agent_name,
  "case_soc_id": "SOAR-HASH",
  "case_customer": 1,
  "case_description": "Malicious hash detected. Rule: " + $('Code').item.json.rule_id + ". Malicious engines: " + $('VirusTotal HTTP Request').item.json.data.attributes.last_analysis_stats.malicious + ". VirusTotal: https://www.virustotal.com/gui/file/" + $('Code').item.json.sha256
})
```

Output: `$json.data.case_id` — the new case ID used by IOC and Asset nodes.

### 3.10 IRIS Add IOC node

- Add **HTTP Request** node after IRIS Add case
- Name it: `IRIS Add ioc`
- Use **Import cURL** button and paste:

```bash
curl -sk -X POST "https://10.10.20.60/case/ioc/add?cid=1" \
  -H "Authorization: Bearer YOUR_SOAR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"ioc_value":"hash","ioc_type_id":113,"ioc_tlp_id":2,"ioc_description":"Malicious hash detected by SOAR.","ioc_tags":"malware"}'
```

After import:
- Update `cid` query param to Expression mode: `$('IRIS Add case').item.json.data.case_id`
- Switch body to **Using JSON**, set field to Expression mode, paste:

```javascript
({
  "ioc_value": $('Code').item.json.sha256,
  "ioc_type_id": 113,
  "ioc_tlp_id": 2,
  "ioc_description": "Malicious hash detected by SOAR.",
  "ioc_tags": "malware"
})
```

> **IOC type IDs for this IRIS installation:** sha256 = 113, TLP:AMBER = 2

### 3.11 IRIS Add Asset node

- Add **HTTP Request** node after IRIS Add case (parallel to IRIS Add ioc)
- Name it: `IRIS Add Assest`
- Use **Import cURL**:

```bash
curl -sk -X POST "https://10.10.20.60/case/assets/add?cid=1" \
  -H "Authorization: Bearer YOUR_SOAR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"asset_name":"ws01","asset_ip":"10.10.10.10","asset_type_id":9,"asset_description":"test","analysis_status_id":1}'
```

After import:
- Update `cid` query param: `$('IRIS Add case').item.json.data.case_id`
- Switch body to **Using JSON**, Expression mode:

```javascript
({
  "asset_name": $('Code').item.json.agent_name,
  "asset_ip": $('Code').item.json.agent_ip,
  "asset_type_id": 9,
  "asset_description": "Malicious binary executed: " + $('Code').item.json.rule_description + ". VT name: " + $('VirusTotal HTTP Request').item.json.data.attributes.meaningful_name,
  "analysis_status_id": 1,
  "asset_tags": $('VirusTotal HTTP Request').item.json.data.attributes.meaningful_name + ",malware," + $('Receive Wazuh Alerts').item.json.body.all_fields.rule.mitre.id[0]
})
```

> **Asset type IDs:** Windows Computer = 9

---

## Part 4 — Activate and test

1. Click **Publish** (top right) — activates the production webhook
2. Update Wazuh ossec.conf hook_url to production URL (not webhook-test)
3. Run mimikatz on ws01
4. Confirm all 5 outputs:
   - Telegram message with host, hash, VT score
   - Email with full VT report link
   - IRIS case created (SOAR-HASH)
   - IRIS IOC added (SHA256, tlp:amber, malware tag)
   - IRIS Asset added (ws01, Windows Computer, mimikatz.exe/malware/T1003.001 tags)

---

## Gotchas and fixes

| Problem | Fix |
|---|---|
| Cloned VM "Cannot find unique matching interface" | Remove `match:` and `set-name:` blocks from netplan |
| SSH fails after clone | `sudo ssh-keygen -A && sudo systemctl restart ssh` |
| n8n "secure cookie" warning | Run with `N8N_PROTOCOL=https` and self-signed cert |
| Wazuh not sending to n8n | Check ossec.log; shuffle.py needs `verify=False` on line 229 |
| Webhook test URL vs production | Production URL only works when workflow is Published |
| VT credential conflicts with URL | Set credential to None, add `x-apikey` header manually |
| IRIS credential "Invalid URL" | Same — credential type prepends base URL, conflicts with full URL in field |
| IRIS SSL cert expired | Regenerate cert in `/home/abel/iris-web/certificates/web_certificates/` |
| n8n expression not evaluating in body | Use "Using JSON" body mode + set body field to Expression mode (fx toggle) → write JS object without `{{ }}` |
| `all_fields` wrapper in Wazuh payload | Wazuh shuffle.py wraps data under `all_fields` — always drag-drop from Schema view |
| 96 test cases in IRIS from Shuffle | Bulk delete: `curl .../manage/cases/list` → pipe case_ids → `curl -X POST .../manage/cases/delete/$id` |
