# Atomic Red Team — Detection Engineering on Sysmon + Splunk
## Detection Engineering Project

**Analyst:** Santiago Abel Ruiz Diaz
**Project ID:** SIEM-2026-0616-ART
**Platform:** Splunk Enterprise 10.4.0 + Sysmon 15.20 (SwiftOnSecurity config)
**Status:** Complete — 9 MITRE ATT&CK techniques simulated and validated against live Sysmon telemetry
**MITRE Coverage:** T1082 · T1003.001 · T1552.001 · T1110.001 · T1083 · T1087.001 · T1135 · T1059.001 · T1547.001 · T1053.005 · T1070.001

Runs on top of the [lab infrastructure](../lab-infrastructure/) — same win-target VM used in [`credential-attack-detection/`](../credential-attack-detection/), now with Sysmon installed for process-, registry-, and file-level visibility beyond what bare Windows Security/System logs provide. Attacks were simulated with [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam), Red Canary's framework for safely executing real MITRE ATT&CK technique samples ("atomics") instead of hand-rolling attacker behavior.

---

## Goal

Stand up Sysmon on an existing detection lab target, wire it into Splunk, and use Invoke-AtomicRedTeam to execute real technique samples across four ATT&CK phases — Credential Access, Discovery, Execution, and Persistence — validating that each one produces a usable detection signal end to end: **atomic → Sysmon → Splunk Universal Forwarder → indexed event**.

---

## Setup — Sysmon + Splunk Pipeline

1. Installed Sysmon 15.20 on win-target, downloading the binary and the [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config) community config separately rather than relying on a bundled package:
   ```powershell
   Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\Sysmon.zip"
   Expand-Archive -Path C:\Sysmon.zip -DestinationPath C:\Sysmon

   Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\Sysmon\sysmonconfig.xml"

   cd C:\Sysmon
   .\Sysmon64.exe -accepteula -i sysmonconfig.xml
   ```
2. Created a new `sysmon` index in Splunk Web (Settings → Indexes → New Index), then added a `[WinEventLog://Microsoft-Windows-Sysmon/Operational]` stanza to the Splunk UF's `inputs.conf`, routing to it.
3. **Gotcha:** `index=sysmon` returned zero results even though Sysmon itself was logging fine (`Get-WinEvent` confirmed real events). `splunkd.log` showed `errorCode=5` (ACCESS_DENIED) when subscribing to the Sysmon channel. Root cause: the Splunk UF service runs as the virtual account `NT SERVICE\SplunkForwarder`, which isn't a member of the local "Event Log Readers" group that the Sysmon channel's ACL grants read access to. Fixed with:
   ```powershell
   Add-LocalGroupMember -Group "Event Log Readers" -Member "NT SERVICE\SplunkForwarder"
   Restart-Service SplunkForwarder
   ```
4. Confirmed the full pipeline with the T1082 baseline atomic (below) before moving on to the real technique set.

---

## Invoke-AtomicRedTeam Setup

```powershell
IEx (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```

Every technique below follows the same loop: `Invoke-AtomicTest <T-code> -ShowDetails` to confirm exactly what will run, then `Invoke-AtomicTest <T-code>` to execute it, then a Splunk search to confirm visibility.

---

## Baseline — T1082 System Information Discovery

Used to validate the pipeline before running anything else.

```spl
index=sysmon EventCode=1 (Image="*systeminfo.exe" OR Image="*reg.exe")
```

**Result:** `systeminfo.exe` and `reg.exe query HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum`, both parented by `cmd.exe`, with full `CommandLine` and `User` fields. Pipeline confirmed working.

[Proof](screenshots/t1082-baseline-confirmed.png) · [`t1082-system-info-discovery.spl`](queries/t1082-system-info-discovery.spl)

---

## Credential Access

### T1003.001 — LSASS Memory Dump (comsvcs.dll)

```powershell
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).id $env:TEMP\lsass-comsvcs.dmp full
```

**Gotcha:** Sysmon's default SwiftOnSecurity config ships with ProcessAccess (EventCode 10) monitoring intentionally disabled — `<ProcessAccess onmatch="include"></ProcessAccess>` with zero rules, because unfiltered process-access logging is extremely high-volume. Without a targeted rule, the actual credential-access signal (a process reaching into `lsass.exe`'s memory) is invisible. Fixed by adding:

```xml
<ProcessAccess onmatch="include">
        <TargetImage condition="end with">lsass.exe</TargetImage>
</ProcessAccess>
```

and hot-reloading with `Sysmon64.exe -c C:\Sysmon\sysmonconfig.xml` (no service restart needed).

**Result:** `rundll32.exe → lsass.exe`, `GrantedAccess=0x1410`, `comsvcs.dll` visible in the call trace — cleanly distinguishable from the benign `svchost.exe → lsass.exe` baseline noise at `GrantedAccess=0x1000` (routine LSA RPC queries). The contrast between the two access masks is the actual detection logic.

[Proof](screenshots/t1003.001-lsass-dump-processaccess.png) · [`t1003.001-lsass-dump.spl`](queries/t1003.001-lsass-dump.spl)

### T1552.001 — Credentials In Files

```powershell
findstr /si pass *.xml *.doc *.txt *.xls
```

**Result:** Clean process-creation event, full command line, parented by PowerShell.

[Proof](screenshots/t1552.001-findstr-credentials.png) · [`t1552.001-credentials-in-files.spl`](queries/t1552.001-credentials-in-files.spl)

### T1110.001 — Brute Force

Already validated against live attack traffic (NetExec/Hydra, 31 + 21 failed logons) in [`credential-attack-detection/`](../credential-attack-detection/). Not re-run here — Invoke-AtomicRedTeam's T1110.001 samples all require an Active Directory domain controller or Azure AD, neither of which exist in this workgroup-only lab.

---

## Discovery

### T1083 — File and Directory Discovery

```cmd
dir /s c:\ >> %temp%\T1083Test1.txt
dir /s "c:\Program Files\" >> %temp%\T1083Test1.txt
tree /F >> %temp%\T1083Test1.txt
```

**Result:** Single chained `cmd.exe /c dir /s c:\ & dir /s "..." & ... & tree /F` command line, captured whole. A single `cmd.exe` invocation chaining multiple full-drive `dir /s` commands is a strong discovery signature — legitimate admin activity rarely looks like this.

[Proof](screenshots/t1083-file-directory-discovery.png) · [`t1083-file-directory-discovery.spl`](queries/t1083-file-directory-discovery.spl)

### T1087.001 — Local Account Discovery

```cmd
net user
net localgroup
net localgroup "Users"
```

**Result:** Three `net.exe → net1.exe` process pairs firing within ~200ms of each other. The sub-second gaps between commands are themselves a tell — no human types this fast; it's scripted enumeration.

[Proof](screenshots/t1087.001-local-account-discovery.png) · [`t1087.001-local-account-discovery.spl`](queries/t1087.001-local-account-discovery.spl)

### T1135 — Network Share Discovery

```cmd
net view \\localhost
```

**Result:** Captured cleanly even with zero shares actually configured on the target — `cmd.exe /c net view \\localhost`, parented by PowerShell. Visibility doesn't depend on the command finding anything.

[Proof](screenshots/t1135-network-share-discovery.png) · [`t1135-network-share-discovery.spl`](queries/t1135-network-share-discovery.spl)

---

## Execution & Persistence

### T1059.001 — PowerShell (Encoded Command)

Ran via Red Canary's `AtomicTestHarnesses` module to exercise switch-variant evasion specifically:

```powershell
Out-ATHPowerShellCommandLineParameter -CommandLineSwitchType Hyphen -EncodedCommandParamVariation E -Execute
```

**Result:** `powershell.exe -NoProfile -E <base64>` — the abbreviated `-E` switch instead of the full `-EncodedCommand`. A detection rule matching only `CommandLine="*-EncodedCommand*"` would miss this entirely. Decoding the base64 payload (UTF-16LE) showed `Write-Host <test-guid>` — the harness proving its own execution, harmless by design.

[Proof](screenshots/t1059.001-encoded-powershell.png) · [`t1059.001-encoded-powershell.spl`](queries/t1059.001-encoded-powershell.spl)

### T1547.001 — Registry Run Keys

```cmd
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Atomic Red Team" /t REG_SZ /F /D "C:\Path\AtomicRedTeam.exe"
```

**Result:** Clean RegistryEvent (EventCode 13) with the full key path and value — Sysmon's default config already watches Run-key paths, no tuning required.

[Proof](screenshots/t1547.001-registry-run-key.png) · [`t1547.001-registry-run-key.spl`](queries/t1547.001-registry-run-key.spl)

### T1053.005 — Scheduled Task

```cmd
SCHTASKS /Create /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe /ST 20:10
```

**Gotcha:** Sysmon caught the `schtasks.exe` process creation immediately, but the native Windows Security-log event for this (EventCode 4698) didn't fire at all — `auditpol /get /subcategory:"Other Object Access Events"` showed "No Auditing." This subcategory is off by default even with basic Security auditing enabled. Fixed with:

```powershell
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
```

Re-ran the atomic after enabling it and got 4698 (`Task_Name=\spawn`) — full double coverage: Sysmon process-creation visibility plus the native, purpose-built Security-log event.

[Sysmon proof](screenshots/t1053.005-schtasks-sysmon.png) · [4698 proof](screenshots/t1053.005-4698-confirmed.png) · [`t1053.005-scheduled-task.spl`](queries/t1053.005-scheduled-task.spl) · [`t1053.005-native-4698.spl`](queries/t1053.005-native-4698.spl)

### T1070.001 — Clear Windows Event Logs

Not available in this Invoke-AtomicRedTeam clone's atomics library, so simulated natively — exactly how a real attacker would do it, no extra tooling required:

```powershell
wevtutil cl Security
```

**Result:** EventCode 1102 fired on `win-target`, logged as essentially the only entry in the freshly-cleared log. An empty Security log immediately followed by a 1102 event is one of the most reliable anti-forensics signals in Windows. Worth noting: clearing the local log doesn't touch evidence already forwarded to Splunk — every event simulated earlier in this project was still indexed and searchable after the clear.

[Proof](screenshots/t1070.001-event-log-cleared.png) · [`t1070.001-clear-windows-event-logs.spl`](queries/t1070.001-clear-windows-event-logs.spl)

---

## Techniques Validated

| Technique | MITRE ID | Signal | Result |
|---|---|---|---|
| System Information Discovery | T1082 | Process creation | ✅ Pipeline baseline confirmed |
| LSASS Memory Dump | T1003.001 | ProcessAccess (after config fix) | ✅ `GrantedAccess=0x1410` vs. `0x1000` baseline |
| Credentials In Files | T1552.001 | Process creation | ✅ `findstr /si pass` captured |
| Brute Force | T1110.001 | — | ✅ Already validated in credential-attack-detection |
| File and Directory Discovery | T1083 | Process creation | ✅ Chained `dir /s` + `tree /F` captured |
| Local Account Discovery | T1087.001 | Process creation | ✅ `net user`/`net localgroup` timing pattern |
| Network Share Discovery | T1135 | Process creation | ✅ `net view \\localhost` captured |
| PowerShell (Encoded Command) | T1059.001 | Process creation | ✅ Abbreviated `-E` switch captured |
| Registry Run Keys | T1547.001 | RegistryEvent | ✅ Run key value captured |
| Scheduled Task | T1053.005 | Process creation + 4698 (after audit policy fix) | ✅ Double coverage confirmed |
| Clear Windows Event Logs | T1070.001 | EventCode 1102 | ✅ Log-clear event captured |

---

## Remediation Recommendations

**Immediate:** Investigate any host generating LSASS `ProcessAccess` events with `GrantedAccess` values outside the routine `0x1000`/`0x1040` range, especially from non-AV/non-EDR processes. Treat a 1102 event with no preceding maintenance ticket as a containment trigger.

**Hardening:** Enable the "Other Object Access Events" audit subcategory fleet-wide via GPO — it's off by default and silently blinds the Security log to scheduled task creation. Add a targeted Sysmon `ProcessAccess` rule for `lsass.exe` (and other sensitive targets like `vaultsvc.exe`) rather than leaving the SwiftOnSecurity default empty. Alert on `-EncodedCommand` AND its abbreviated forms (`-e`, `-en`, `-enc`) — don't rely on a single string match.

**Strategic:** Credential Guard / LSA Protection (`RunAsPPL`) to block userland process access to LSASS entirely, regardless of detection coverage. Centralize log forwarding (already done here) so local log clearing never erases the analyst's evidence.

---

## Related

- [`lab-infrastructure/`](../lab-infrastructure/) — the Proxmox/OPNsense/Splunk build this runs on
- [`credential-attack-detection/`](../credential-attack-detection/) — the brute force / password spray detections this project builds on
- [`future-work/`](../future-work/) — firewall/IDS-layer detections, not yet validated
