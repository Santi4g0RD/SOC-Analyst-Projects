# Environment Setup

## Prerequisites

- A Virtual Machine onboarded to Microsoft Defender for Endpoint (MDE)
- Verify the device appears in the `DeviceInfo` table in MDE Advanced Hunting

## Steps

### 1. Provision the Virtual Machine
Follow the [VM provisioning guide](https://docs.google.com/document/d/1o7I2MsZPgSH24LNC4aEr98tAu4nKpgYRSnxNY0VZYUQ/edit#bookmark=id.398eet66ipbv).

### 2. Onboard the VM to MDE
Follow [Part 1 of the MDE onboarding guide](https://docs.google.com/document/d/1MmwEqZ2ZEgKQA6UDj0otads6EnleBg2yxC01vGYuRSw/edit) (stop after Part 1).

### 3. Verify Logs Are Flowing
In MDE Advanced Hunting, run:
```kql
DeviceInfo
| where DeviceName == "abel-win11-vm"
| order by Timestamp desc
| take 5
```
Confirm recent entries appear before proceeding.

### 4. Disable MDE App Restrictions (if TOR install is blocked)
MDE may block the TOR installer by default. To remove restrictions:

1. Navigate to [https://security.microsoft.com/](https://security.microsoft.com/)
2. Go to **Assets > Devices** and search for your VM
3. Click the device, then select **Remove App Restrictions** from the right-side menu
4. Enter a reason and confirm
5. Re-attempt the TOR installation
