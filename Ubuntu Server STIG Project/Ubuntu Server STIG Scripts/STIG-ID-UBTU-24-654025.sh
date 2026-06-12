#!/bin/bash
#
# .SYNOPSIS
#     This script disables SSH root login on Ubuntu Server 24.04.
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
#     STIG-ID         : UBTU-24-654025
#
# .TESTED ON
#     Date(s) Tested  :
#     Tested By       :
#     Systems Tested  :
#     Shell Ver.      :
#
# .USAGE
#     Run with sudo privileges.
#     Example syntax:
#     sudo bash STIG-ID-UBTU-24-654025.sh

SSHD_CONF="/etc/ssh/sshd_config"

if grep -q "^PermitRootLogin" "$SSHD_CONF"; then
    sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONF"
else
    echo "PermitRootLogin no" >> "$SSHD_CONF"
fi

systemctl restart sshd

echo "SSH root login has been disabled."
