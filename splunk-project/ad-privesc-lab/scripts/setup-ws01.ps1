# setup-ws01.ps1
# Run on win-target (192.168.10.10) as Administrator
# Repurposes win-target as ws01.soclab.local
# Management workstation + PrivEsc lab lateral movement target

# --- Step 1: Set DNS to DC before domain join ---
$adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses "192.168.10.11"
Write-Host "[+] DNS set to 192.168.10.11 (win-dc)" -ForegroundColor Green

# Verify DC is reachable
if (Test-Connection -ComputerName 192.168.10.11 -Count 1 -Quiet) {
    Write-Host "[+] DC reachable" -ForegroundColor Green
} else {
    Write-Host "[!] Cannot reach DC - check network before continuing" -ForegroundColor Red
    exit 1
}

# --- Step 2: Rename and join domain ---
Write-Host "[*] Joining soclab.local as ws01..." -ForegroundColor Cyan
$cred = Get-Credential -Message "Enter soclab.local\Administrator credentials"

Add-Computer -DomainName "soclab.local" `
             -NewName "ws01" `
             -Credential $cred `
             -Force `
             -ErrorAction Stop

Write-Host "[+] Renamed to ws01 and joined soclab.local" -ForegroundColor Green

# --- Step 3: Install RSAT tools ---
Write-Host "[*] Installing RSAT tools..." -ForegroundColor Cyan
Install-WindowsFeature RSAT-AD-Tools -IncludeAllSubFeature -IncludeManagementTools | Out-Null
Install-WindowsFeature RSAT-DNS-Server | Out-Null
Write-Host "[+] RSAT installed" -ForegroundColor Green

# --- Step 4: Re-enable Windows Firewall ---
Write-Host "[*] Re-enabling Windows Firewall..." -ForegroundColor Cyan
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Write-Host "[+] Firewall enabled" -ForegroundColor Green

# --- Step 5: Re-enable Windows Defender ---
Write-Host "[*] Re-enabling Windows Defender..." -ForegroundColor Cyan
Set-MpPreference -DisableRealtimeMonitoring $false
Write-Host "[+] Defender enabled" -ForegroundColor Green

# --- Step 6: Install Wazuh agent ---
Write-Host "[*] Installing Wazuh agent..." -ForegroundColor Cyan
$wazuhInstaller = "$env:TEMP\wazuh-agent.msi"
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.12.0-1.msi" `
                  -OutFile $wazuhInstaller
msiexec.exe /i $wazuhInstaller `
            WAZUH_MANAGER="192.168.10.20" `
            WAZUH_AGENT_NAME="ws01" `
            /quiet /norestart
Write-Host "[+] Wazuh agent installed - manager: 192.168.10.20" -ForegroundColor Green

# --- Step 7: Restart ---
Write-Host ""
Write-Host "[*] Setup complete. Restarting in 10 seconds..." -ForegroundColor Yellow
Write-Host "    After restart: log in as soclab\Administrator" -ForegroundColor Yellow
Write-Host "    Then start Wazuh: Start-Service WazuhSvc" -ForegroundColor Yellow
Start-Sleep -Seconds 10
Restart-Computer -Force
