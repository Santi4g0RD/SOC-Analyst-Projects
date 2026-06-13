#!/bin/bash
#
# .SYNOPSIS
#     This script sets the audit log file size to 10 MB or greater on Ubuntu Server 24.04.
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
#     STIG-ID         : UBTU-24-010014
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
#     sudo bash STIG-ID-UBTU-24-010014.sh

AUDITD_CONF="/etc/audit/auditd.conf"

if grep -q "^max_log_file " "$AUDITD_CONF"; then
    sed -i 's/^max_log_file .*/max_log_file = 10/' "$AUDITD_CONF"
else
    echo "max_log_file = 10" >> "$AUDITD_CONF"
fi

systemctl restart auditd

echo "Audit log max file size set to 10 MB."
