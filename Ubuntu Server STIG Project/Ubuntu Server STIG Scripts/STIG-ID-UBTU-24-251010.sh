#!/bin/bash
#
# .SYNOPSIS
#     This script disables the USB storage module on Ubuntu Server 24.04.
#
# .NOTES
#     Author          : Santiago Abel Ruiz Diaz
#     LinkedIn        : linkedin.com/in/santiago-a-ruiz-diaz-4aa418b2/
#     GitHub          : github.com/Santi4g0RD
#     Date Created    : 2026-06-10
#     Last Modified   : 2026-06-10
#     Version         : 1.0
#     CVEs            : N/A
#     Plugin IDs      : N/A
#     STIG-ID         : UBTU-24-251010
#
# .TESTED ON
#     Date(s) Tested  : 2026-06-13
#     Tested By       : Santiago Abel Ruiz Diaz
#     Systems Tested  : Ubuntu Server 24.04 LTS — Microsoft Azure
#     Shell Ver.      :
#
# .USAGE
#     Run with sudo privileges.
#     Example syntax:
#     sudo bash STIG-ID-UBTU-24-251010.sh

echo "install usb-storage /bin/false" > /etc/modprobe.d/usb-storage.conf
echo "blacklist usb-storage" >> /etc/modprobe.d/usb-storage.conf

modprobe -r usb-storage 2>/dev/null

echo "USB storage module has been disabled."
