# Environment Setup

## Prerequisites

- A Windows 11 Virtual Machine (Azure, VMware, or equivalent)
- At least 4GB RAM and internet access on the VM
- A Microsoft Defender for Endpoint (MDE) license or trial workspace

## Steps

### 1. Provision the Virtual Machine
Deploy a Windows 11 VM using your preferred platform (Azure, VMware, Hyper-V, etc.). Ensure the
VM has outbound internet access so MDE can communicate with the cloud portal.

### 2. Onboard the VM to MDE
1. Navigate to [https://security.microsoft.com/](https://security.microsoft.com/)
2. Go to **Settings > Endpoints > Onboarding**
3. Select **Windows 10 and 11** as the OS
4. Download the onboarding package and run it on the VM as Administrator
5. Wait 5–10 minutes for the device to appear in the MDE portal under **Assets > Devices**

### 3. Verify Logs Are Flowing
In MDE Advanced Hunting, confirm the device is reporting by running:
```kql
DeviceInfo
| where DeviceName == "abel-win11-vm"
| order by Timestamp desc
| take 5
```
Confirm recent entries appear before proceeding to the attack simulation.

### 4. Disable MDE App Restrictions (if TOR install is blocked)
MDE may block the TOR installer by default. To remove restrictions:

1. Navigate to [https://security.microsoft.com/](https://security.microsoft.com/)
2. Go to **Assets > Devices** and search for your VM
3. Click the device, then select **Remove App Restrictions** from the right-side menu
4. Enter a reason and confirm
5. Re-attempt the TOR installation
