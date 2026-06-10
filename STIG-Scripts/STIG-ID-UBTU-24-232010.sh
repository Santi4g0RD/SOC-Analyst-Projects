#!/bin/bash
#
# .SYNOPSIS
#     This script sets the minimum password length to 15 characters on Ubuntu Server 24.04.
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
#     STIG-ID         : UBTU-24-232010
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
#     sudo bash STIG-ID-UBTU-24-232010.sh

COMMON_PASSWD="/etc/security/pwquality.conf"

if grep -q "^minlen" "$COMMON_PASSWD"; then
    sed -i 's/^minlen.*/minlen = 15/' "$COMMON_PASSWD"
else
    echo "minlen = 15" >> "$COMMON_PASSWD"
fi

echo "Minimum password length set to 15 characters."
