#!/bin/bash
#
# .SYNOPSIS
#     This script enables and configures the UFW firewall on Ubuntu Server 24.04.
#
# .NOTES
#     Author          : Santiago Abel Ruiz Diaz
#     LinkedIn        : linkedin.com/in/
#     GitHub          : github.com/
#     Date Created    : 2026-06-10
#     Last Modified   : 2026-06-10
#     Version         : 1.0
#     CVEs            : N/A
#     Plugin IDs      : N/A
#     STIG-ID         : UBTU-24-412010
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
#     sudo bash STIG-ID-UBTU-24-412010.sh

apt-get install -y ufw

ufw --force enable
ufw default deny incoming
ufw default allow outgoing

echo "UFW firewall has been enabled with default deny incoming policy."
