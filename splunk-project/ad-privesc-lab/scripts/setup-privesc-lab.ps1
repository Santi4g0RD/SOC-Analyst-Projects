# setup-privesc-lab.ps1
# Run on win-dc (192.168.10.11) as Domain Administrator
# Creates new users and sets ACL attack path for AD PrivEsc lab:
#   agarcia --GenericWrite--> mbrown --DS-Replication--> Domain

Import-Module ActiveDirectory

Write-Host "=== AD PrivEsc Lab Setup ===" -ForegroundColor Cyan
Write-Host "Domain: soclab.local | DC: win-dc.soclab.local" -ForegroundColor Cyan
Write-Host ""

# -- Step 1: Create users ---------------------------------------------------
Write-Host "[*] Creating domain users..." -ForegroundColor Cyan

$users = @(
    @{ Name="Alex Garcia";    Sam="agarcia";  Pass="Spring2025!" },
    @{ Name="Marcus Brown";   Sam="mbrown";   Pass="Password123!" },
    @{ Name="Lisa Wilson";    Sam="lwilson";  Pass="Spring2025!" },
    @{ Name="David Baker";    Sam="dbaker";   Pass="Spring2025!" }
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

# -- Step 2: Set SPN on mbrown (Kerberoasting target) ----------------------
Write-Host "[*] Setting SPN on mbrown..." -ForegroundColor Cyan
Set-ADUser -Identity mbrown `
           -ServicePrincipalNames @{Add="HTTPSvc/fake.soclab.local:8080"}
Write-Host "  [+] SPN: HTTPSvc/fake.soclab.local:8080" -ForegroundColor Green

# -- Step 3: Allow RC4 on mbrown (so hash is crackable with rockyou) -------
Write-Host "[*] Enabling RC4 for mbrown..." -ForegroundColor Cyan
Set-ADUser -Identity mbrown -KerberosEncryptionType RC4,AES128,AES256
Write-Host "  [+] RC4 + AES128 + AES256 allowed for mbrown" -ForegroundColor Green

# -- Step 4: GenericWrite -agarcia over mbrown ----------------------------
Write-Host "[*] Setting GenericWrite ACE: agarcia -> mbrown..." -ForegroundColor Cyan

$mbrown     = Get-ADUser mbrown
$agarcia    = Get-ADUser agarcia
$agarciaSID = [System.Security.Principal.SecurityIdentifier] $agarcia.SID

$mbownDN  = "AD:$($mbrown.DistinguishedName)"
$acl      = Get-Acl $mbownDN
$ace      = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $agarciaSID,
    [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite,
    [System.Security.AccessControl.AccessControlType]::Allow
)
$acl.AddAccessRule($ace)
Set-Acl -Path $mbownDN -AclObject $acl
Write-Host "  [+] agarcia has GenericWrite on mbrown" -ForegroundColor Green

# -- Step 5: DS-Replication rights -mbrown on domain ---------------------
# Grants mbrown the same replication rights as a DC -enables DCSync
Write-Host "[*] Setting DS-Replication rights: mbrown -> Domain..." -ForegroundColor Cyan

$domain    = Get-ADDomain
$domainDN  = "AD:$($domain.DistinguishedName)"
$aclDomain = Get-Acl $domainDN
$mbrownSID = [System.Security.Principal.SecurityIdentifier] (Get-ADUser mbrown).SID

# DS-Replication-Get-Changes
$guid1 = [GUID]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
$ace1  = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $mbrownSID,
    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
    [System.Security.AccessControl.AccessControlType]::Allow,
    $guid1,
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
)

# DS-Replication-Get-Changes-All
$guid2 = [GUID]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
$ace2  = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $mbrownSID,
    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
    [System.Security.AccessControl.AccessControlType]::Allow,
    $guid2,
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
)

$aclDomain.AddAccessRule($ace1)
$aclDomain.AddAccessRule($ace2)
Set-Acl -Path $domainDN -AclObject $aclDomain
Write-Host "  [+] mbrown has DS-Replication-Get-Changes on domain" -ForegroundColor Green
Write-Host "  [+] mbrown has DS-Replication-Get-Changes-All on domain" -ForegroundColor Green

# -- Step 6: Enable audit policies for better detection coverage ------------
Write-Host "[*] Enabling audit policies..." -ForegroundColor Cyan
auditpol /set /subcategory:"Directory Service Access" /success:enable | Out-Null
auditpol /set /subcategory:"Kerberos Authentication Service" /failure:enable | Out-Null
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable | Out-Null
Write-Host "  [+] Directory Service Access (4662) -success" -ForegroundColor Green
Write-Host "  [+] Kerberos Authentication Service (4768) -failure" -ForegroundColor Green
Write-Host "  [+] Other Object Access Events (4698) -success/failure" -ForegroundColor Green

# -- Step 7: Configure ws01 local groups for pivot access -----------------
# Allows agarcia to RDP and WinRM into ws01 — required for the lateral
# movement phase (Kali -> ws01 -> DC). ws01 must be domain-joined first.
Write-Host "[*] Configuring ws01 local groups for agarcia..." -ForegroundColor Cyan
try {
    Invoke-Command -ComputerName ws01.soclab.local -ScriptBlock {
        Add-LocalGroupMember -Group "Remote Desktop Users"   -Member "SOCLAB\agarcia" -ErrorAction SilentlyContinue
        Add-LocalGroupMember -Group "Remote Management Users" -Member "SOCLAB\agarcia" -ErrorAction SilentlyContinue
    } -ErrorAction Stop
    Write-Host "  [+] agarcia -> Remote Desktop Users (ws01)" -ForegroundColor Green
    Write-Host "  [+] agarcia -> Remote Management Users (ws01)" -ForegroundColor Green
} catch {
    Write-Host "  [!] Could not reach ws01 - run manually after ws01 joins domain:" -ForegroundColor Yellow
    Write-Host "      Add-LocalGroupMember -Group 'Remote Desktop Users' -Member 'SOCLAB\agarcia'" -ForegroundColor Yellow
    Write-Host "      Add-LocalGroupMember -Group 'Remote Management Users' -Member 'SOCLAB\agarcia'" -ForegroundColor Yellow
}

# -- Step 8: Summary -------------------------------------------------------
Write-Host ""
Write-Host "=== Setup Complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "Attack path:" -ForegroundColor Yellow
Write-Host "  agarcia (Spring2025!) --GenericWrite--> mbrown --DS-Replication--> Domain" -ForegroundColor Yellow
Write-Host ""
Write-Host "Users:" -ForegroundColor Yellow
Write-Host "  agarcia  / Spring2025!  -standard user (spray target)" -ForegroundColor White
Write-Host "  mbrown   / Password123! -service account, SPN set, DCSync rights" -ForegroundColor White
Write-Host "  lwilson  / Spring2025!  -standard user" -ForegroundColor White
Write-Host "  dbaker   / Spring2025!  -standard user" -ForegroundColor White
Write-Host ""
Write-Host "Audit policies enabled: 4662, 4768 failures, 4698" -ForegroundColor Yellow
Write-Host "Spray wordlist: ~/lab/ad-users2.txt (agarcia, mbrown, lwilson, dbaker)" -ForegroundColor Yellow
Write-Host "ws01 local groups: agarcia in Remote Desktop Users + Remote Management Users" -ForegroundColor Yellow
