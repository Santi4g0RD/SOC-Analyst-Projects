# n8n SOAR — Next Session Build Plan

**Date:** 2026-07-09  
**Session goal:** Complete the SOAR pipeline with network/spray branch, AI triage, Wazuh Active Response, and end-to-end attack run.

---

## Phase A — Network/spray branch in n8n

Pick up from the **false output** of the IF node (no SHA256 in payload = spray/network alert).

### A.1 AbuseIPDB enrichment

- Add **HTTP Request** node on false IF output
- Method: GET
- URL: `https://api.abuseipdb.com/api/v2/check`
- Send Query Parameters:
  - `ipAddress`: `{{ $('Receive Wazuh Alerts').item.json.body.all_fields.data.win.eventdata.ipAddress }}`
  - `maxAgeInDays`: `90`
- Send Headers:
  - `Key`: your AbuseIPDB API key
  - `Accept`: `application/json`

Key output fields:
- `$json.data.ipAddress` — source IP
- `$json.data.abuseConfidenceScore` — 0–100
- `$json.data.countryCode`
- `$json.data.totalReports`

### A.2 AI Triage node (Anthropic Claude API)

After AbuseIPDB, add **HTTP Request** to Claude API:

- Method: POST
- URL: `https://api.anthropic.com/v1/messages`
- Headers:
  - `x-api-key`: your Anthropic API key
  - `anthropic-version`: `2023-06-01`
  - `Content-Type`: `application/json`
- Body (Expression mode):

```javascript
({
  "model": "claude-haiku-4-5-20251001",
  "max_tokens": 300,
  "messages": [{
    "role": "user",
    "content": "You are a SOC analyst. Analyze this alert and respond in JSON with fields: classification (Confirmed Threat / Suspicious / Likely False Positive), confidence (High / Medium / Low), recommended_action (BLOCK / INVESTIGATE / DISMISS), brief (2 sentences max).\n\nAlert data:\nRule: " + $('Receive Wazuh Alerts').item.json.body.all_fields.rule.description + "\nMITRE: " + $('Receive Wazuh Alerts').item.json.body.all_fields.rule.mitre.id[0] + "\nSource IP: " + $('AbuseIPDB').item.json.data.ipAddress + "\nAbuseIPDB Score: " + $('AbuseIPDB').item.json.data.abuseConfidenceScore + "%\nTotal Reports: " + $('AbuseIPDB').item.json.data.totalReports + "\nAgent: " + $('Receive Wazuh Alerts').item.json.body.all_fields.agent.name
  }]
})
```

> Same AI triage node goes in the hash pipeline too — after VirusTotal, feed VT score + MITRE + rule into Claude for hash classification.

Key output: `$json.content[0].text` — parse as JSON for classification/brief fields.

### A.3 Telegram alert

- Add **Telegram** node after AI triage
- Text:

```
🌐 NETWORK ALERT

Host: {{ $('Receive Wazuh Alerts').item.json.body.all_fields.agent.name }}
Source IP: {{ $('AbuseIPDB').item.json.data.ipAddress }}
AbuseIPDB Score: {{ $('AbuseIPDB').item.json.data.abuseConfidenceScore }}%
Rule: {{ $('Receive Wazuh Alerts').item.json.body.all_fields.rule.description }}
Time: {{ $('Receive Wazuh Alerts').item.json.body.all_fields.timestamp }}

🤖 AI Assessment: {{ JSON.parse($('AI Triage').item.json.content[0].text).classification }} — {{ JSON.parse($('AI Triage').item.json.content[0].text).brief }}

Recommended: {{ JSON.parse($('AI Triage').item.json.content[0].text).recommended_action }}

Check email for BLOCK/INVESTIGATE decision.
```

### A.4 Analyst approval email

- Add **Send Email** node after Telegram
- Subject: `🌐 ACTION REQUIRED — {{ $('Receive Wazuh Alerts').item.json.body.all_fields.agent.name }} spray alert`
- Body includes AbuseIPDB score, AI brief, and the Wait node resume URLs

### A.5 Wait node (analyst approval)

- Add **Wait** node after email
- Resume: **On webhook call**
- Limit wait time: 1 hour (auto-INVESTIGATE if no response)
- The resume URL is available at `{{ $execution.resumeUrl }}`
- Add `?action=BLOCK` and `?action=INVESTIGATE` to the URL in the email

### A.6 IF node — BLOCK vs INVESTIGATE

- Condition: `{{ $json.query.action }}` equals `BLOCK`
- True → BLOCK path
- False → INVESTIGATE path

### A.7 BLOCK path

1. **OPNsense add** — HTTP Request (curl method):
   ```bash
   curl -k -u "KEY:SECRET" -X POST -H "Content-Type: application/json" \
     -d '{"address": "{{ $('Receive Wazuh Alerts').item.json.body.all_fields.data.win.eventdata.ipAddress }}"}' \
     https://10.10.20.1/api/firewall/alias_util/add/blocklist
   ```
2. **OPNsense reconfigure** — HTTP Request
3. **IRIS case** — POST `/manage/cases/add` with case_name `BLOCKED - Spray from <IP>`
4. **Telegram confirmed** — "✅ IP blocked. Case #X created. Auto-unblock in 1 hour."
5. **Wait** — 1 hour (fixed duration)
6. **OPNsense delete** — remove IP from blocklist
7. **OPNsense reconfigure** — apply
8. **Telegram unblocked** — "🔓 IP auto-unblocked after 1 hour."

### A.8 INVESTIGATE path

1. **IRIS case** — POST `/manage/cases/add` with case_name `INVESTIGATE - Spray from <IP>`, state Open
2. **Telegram** — "📋 IP flagged for investigation. Case #X created. No block applied."

---

## Phase B — Wazuh Active Response (endpoint isolation)

Triggered on the BLOCK path after OPNsense blocks the IP — isolate the source host at the endpoint level.

### B.1 How Wazuh AR works

Wazuh manager sends a command to the agent via the AR module. The agent runs a local script that drops all network traffic except the Wazuh manager connection (so the agent stays managed).

### B.2 AR script on ws01

On ws01, create the isolation script at `C:\Program Files (x86)\ossec-agent\active-response\bin\isolate-host.ps1`:

```powershell
# Block all inbound/outbound except Wazuh manager (10.10.20.20)
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound
netsh advfirewall firewall add rule name="Allow Wazuh" dir=out action=allow remoteip=10.10.20.20
netsh advfirewall firewall add rule name="Allow Wazuh In" dir=in action=allow remoteip=10.10.20.20
```

### B.3 Register AR in Wazuh manager

In `/var/ossec/etc/ossec.conf` on the Wazuh manager:

```xml
<command>
  <name>isolate-host</name>
  <executable>isolate-host.ps1</executable>
  <timeout_allowed>no</timeout_allowed>
</command>

<active-response>
  <disabled>no</disabled>
  <command>isolate-host</command>
  <location>local</location>
</active-response>
```

### B.4 Trigger AR from n8n

Add HTTP Request node on BLOCK path to call Wazuh API:

- Method: PUT
- URL: `https://10.10.20.20:55000/active-response`
- Headers: Wazuh JWT token (get with `POST /security/user/authenticate`)
- Body:
```json
{
  "command": "isolate-host",
  "arguments": [],
  "alert": {"data": {"srcip": "{{ $('Receive Wazuh Alerts').item.json.body.all_fields.data.win.eventdata.ipAddress }}"}}
}
```

---

## Phase C — AI triage in hash pipeline

Go back to the hash pipeline and add the AI Triage node after VirusTotal:

- Same Claude API call, different prompt context:

```
Rule: <rule_description>
MITRE: T1003.001
SHA256: <hash>
VT Malicious: 63/72 engines
VT Name: mimikatz.exe
Agent: ws01
```

Claude output goes into:
- IRIS case description (AI brief appended)
- Analyst email (AI recommendation section)
- Telegram (AI assessment line)

---

## Phase D — End-to-end attack run + documentation

### D.1 Hash pipeline test
1. Run mimikatz on ws01
2. Confirm: Telegram ✅ → Email ✅ → AI triage ✅ → IRIS case/IOC/asset ✅

### D.2 Network pipeline test
1. Run spray from Kali (10.10.30.100)
2. Confirm: AbuseIPDB ✅ → AI triage ✅ → Telegram ✅ → Email with Wait URL ✅
3. Click BLOCK link → OPNsense blocks ✅ → IRIS case ✅ → auto-unblock ✅

### D.3 Incident response report
Write IR report for the spray → BLOCK scenario:
- Timeline with timestamps
- Evidence (Wazuh alert, AbuseIPDB output, AI assessment, OPNsense block confirmation, IRIS case)
- Same format as IR-2026-001 (AD privesc report)

---

## Notes and reminders

- ossec.conf uses production URL: `https://10.10.20.80:5678/webhook/wazuh-alerts`
- n8n workflow must be **Published** for production webhook to work
- IRIS API key: SOAR service account (IRIS → Advanced → Users → soar)
- OPNsense API: shuffle user, `blocklist` alias, VLAN 20 segment
- AbuseIPDB spray IP: `$json.body.all_fields.data.win.eventdata.ipAddress` (NOT data.srcip)
- Anthropic API: use `claude-haiku-4-5-20251001` for speed and cost in the pipeline
- AI response is at: `$json.content[0].text` — parse with `JSON.parse()`
