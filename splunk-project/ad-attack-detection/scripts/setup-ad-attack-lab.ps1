# setup-ad-attack-lab.ps1
# Run on win-dc as Domain Administrator
# Sets up the AD Attack Detection Lab:
#   - 5 domain users (shared weak password — spray scenario)
#   - jsmith elevated to Domain Admin (DA access via single spray hit)
#   - sconnor has SPN + RC4 allowed (Kerberoasting target)
#   - Audit policies enabled for full detection coverage

Import-Module ActiveDirectory

Write-Host "=== AD Attack Detection Lab Setup ===" -ForegroundColor Cyan
Write-Host "Domain: soclab.local | DC: win-dc.soclab.local" -ForegroundColor Cyan
Write-Host ""

# -- Step 1: Create users ---------------------------------------------------
Write-Host "[*] Creating domain users..." -ForegroundColor Cyan

$users = @(
    @{ Name="John Smith";      Sam="jsmith";    Pass="Winter2025!" },
    @{ Name="Sarah Connor";    Sam="sconnor";   Pass="Winter2025!" },
    @{ Name="Tom Baker";       Sam="tbaker";    Pass="Winter2025!" },
    @{ Name="Luis Martinez";   Sam="lmartinez"; Pass="Winter2025!" },
    @{ Name="Karen Thomas";    Sam="kthomas";   Pass="Winter2025!" }
)

foreach ($u in $users) {
    $secPass = ConvertTo-SecureString $u.Pass -AsPlainText -Force
    New-ADUser -Name $u.Name `
               -SamAccountName $u.Sam `
               -UserPrincipalName "$($u.Sam)@soclab.local" `
               -AccountPassword $secPass `
               -Enabled $true `
               -PasswordNeverExpires $true `
               -ErrorAction SilentlyContinue
    Write-Host "  [+] $($u.Sam) ($($u.Name))" -ForegroundColor Green
}

# -- Step 2: Add jsmith to Domain Admins ------------------------------------
Write-Host "[*] Elevating jsmith to Domain Admin..." -ForegroundColor Cyan
Add-ADGroupMember -Identity "Domain Admins" -Members "jsmith"
Write-Host "  [+] jsmith -> Domain Admins" -ForegroundColor Green

# -- Step 3: Set SPN on sconnor (Kerberoasting target) ----------------------
Write-Host "[*] Setting SPN on sconnor..." -ForegroundColor Cyan
Set-ADUser -Identity sconnor `
           -ServicePrincipalNames @{Add="MSSQLSvc/win-dc.soclab.local:1433"}
Write-Host "  [+] SPN: MSSQLSvc/win-dc.soclab.local:1433" -ForegroundColor Green

# -- Step 4: Allow RC4 on sconnor (so TGS hash is crackable) ---------------
# WS2025 defaults to AES-only. RC4 must be explicitly re-enabled on the
# target account for hashcat -m 13100 to work against rockyou.
Write-Host "[*] Enabling RC4 for sconnor..." -ForegroundColor Cyan
Set-ADUser -Identity sconnor -KerberosEncryptionType RC4,AES128,AES256
Write-Host "  [+] RC4 + AES128 + AES256 allowed for sconnor" -ForegroundColor Green

# -- Step 5: Enable audit policies ------------------------------------------
# These are off by default on WS2025 and make DCSync and AS-REP
# probes completely invisible without them.
Write-Host "[*] Enabling audit policies..." -ForegroundColor Cyan
auditpol /set /subcategory:"Directory Service Access"          /success:enable | Out-Null
auditpol /set /subcategory:"Kerberos Authentication Service"   /failure:enable | Out-Null
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable | Out-Null
Write-Host "  [+] Directory Service Access (EventCode 4662) - success" -ForegroundColor Green
Write-Host "  [+] Kerberos Authentication Service (EventCode 4768) - failure" -ForegroundColor Green
Write-Host "  [+] Kerberos Service Ticket Operations (EventCode 4769) - success/failure" -ForegroundColor Green

# -- Step 6: Create spray wordlist on Kali-accessible share -----------------
# Saves the wordlist locally; copy to Kali manually or via SCP.
$wordlistDir  = "C:\lab"
$wordlistPath = "$wordlistDir\ad-attack-users.txt"
if (-not (Test-Path $wordlistDir)) { New-Item -ItemType Directory -Path $wordlistDir | Out-Null }
@"
jsmith
sconnor
tbaker
lmartinez
kthomas
administrator
"@ | Set-Content -Path $wordlistPath -Encoding ASCII
Write-Host "[*] Wordlist saved to $wordlistPath" -ForegroundColor Cyan
Write-Host "  [+] Copy to Kali: scp $wordlistPath kali@10.10.30.100:~/lab/ad-attack/ad-users.txt" -ForegroundColor Yellow

# -- Step 7: Verify setup ---------------------------------------------------
Write-Host ""
Write-Host "[*] Verifying..." -ForegroundColor Cyan

Write-Host "  Domain Admins members:" -ForegroundColor White
(Get-ADGroupMember "Domain Admins").SamAccountName | ForEach-Object { Write-Host "    $_" -ForegroundColor White }

Write-Host "  sconnor SPN:" -ForegroundColor White
(Get-ADUser sconnor -Properties ServicePrincipalNames).ServicePrincipalNames | ForEach-Object { Write-Host "    $_" -ForegroundColor White }

Write-Host "  sconnor KerberosEncryptionType:" -ForegroundColor White
(Get-ADUser sconnor -Properties KerberosEncryptionType).KerberosEncryptionType | ForEach-Object { Write-Host "    $_" -ForegroundColor White }

Write-Host ""
Write-Host "=== Setup Complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "Attack chain:" -ForegroundColor Yellow
Write-Host "  Spray Winter2025! -> jsmith (Pwn3d! DA) -> Enumerate -> Kerb. sconnor -> DCSync" -ForegroundColor Yellow
Write-Host ""
Write-Host "Users (all share Winter2025!):" -ForegroundColor Yellow
Write-Host "  jsmith    / Winter2025!  - Domain Admin (spray hit -> full DA access)" -ForegroundColor White
Write-Host "  sconnor   / Winter2025!  - service account, SPN set (Kerberoasting target)" -ForegroundColor White
Write-Host "  tbaker    / Winter2025!  - standard user (spray target)" -ForegroundColor White
Write-Host "  lmartinez / Winter2025!  - standard user (spray target)" -ForegroundColor White
Write-Host "  kthomas   / Winter2025!  - standard user (spray target)" -ForegroundColor White
Write-Host ""
Write-Host "Audit policies enabled:" -ForegroundColor Yellow
Write-Host "  4662 - Directory Service Access (DCSync detection)" -ForegroundColor White
Write-Host "  4768 - Kerberos Auth failures (AS-REP Roasting detection)" -ForegroundColor White
Write-Host "  4769 - Kerberos TGS requests (Kerberoasting detection)" -ForegroundColor White
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Copy wordlist to Kali: ~/lab/ad-attack/ad-users.txt" -ForegroundColor White
Write-Host "  2. Verify Wazuh agent active on win-dc" -ForegroundColor White
Write-Host "  3. Verify Splunk UF forwarding: index=wineventlog ComputerName=win-dc.soclab.local" -ForegroundColor White
Write-Host "  4. Start Phase 1 - nmap 10.10.10.11" -ForegroundColor White
