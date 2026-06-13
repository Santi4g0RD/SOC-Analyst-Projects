#!/bin/bash
#
# .SYNOPSIS
#     This script sets the SSH client alive interval to prevent unattended sessions on Ubuntu Server 24.04.
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
#     STIG-ID         : UBTU-24-255010
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
#     sudo bash STIG-ID-UBTU-24-255010.sh

SSHD_CONF="/etc/ssh/sshd_config"

if grep -q "^ClientAliveInterval" "$SSHD_CONF"; then
    sed -i 's/^ClientAliveInterval.*/ClientAliveInterval 600/' "$SSHD_CONF"
else
    echo "ClientAliveInterval 600" >> "$SSHD_CONF"
fi

if grep -q "^ClientAliveCountMax" "$SSHD_CONF"; then
    sed -i 's/^ClientAliveCountMax.*/ClientAliveCountMax 0/' "$SSHD_CONF"
else
    echo "ClientAliveCountMax 0" >> "$SSHD_CONF"
fi

systemctl restart sshd

echo "SSH session timeout set to 10 minutes of inactivity."
