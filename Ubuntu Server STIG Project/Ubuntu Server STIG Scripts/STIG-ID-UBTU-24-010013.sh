#!/bin/bash
#
# .SYNOPSIS
#     This script ensures the auditd service is enabled and running on Ubuntu Server 24.04.
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
#     STIG-ID         : UBTU-24-010013
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
#     sudo bash STIG-ID-UBTU-24-010013.sh

apt-get install -y auditd audispd-plugins

systemctl enable auditd
systemctl start auditd

echo "auditd has been installed, enabled, and started."
