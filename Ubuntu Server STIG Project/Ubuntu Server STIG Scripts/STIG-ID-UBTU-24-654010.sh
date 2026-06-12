#!/bin/bash
#
# .SYNOPSIS
#     This script configures account lockout after 3 failed login attempts on Ubuntu Server 24.04.
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
#     STIG-ID         : UBTU-24-654010
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
#     sudo bash STIG-ID-UBTU-24-654010.sh

FAILLOCK_CONF="/etc/security/faillock.conf"

if grep -q "^deny" "$FAILLOCK_CONF" 2>/dev/null; then
    sed -i 's/^deny.*/deny = 3/' "$FAILLOCK_CONF"
else
    echo "deny = 3" >> "$FAILLOCK_CONF"
fi

if grep -q "^unlock_time" "$FAILLOCK_CONF" 2>/dev/null; then
    sed -i 's/^unlock_time.*/unlock_time = 900/' "$FAILLOCK_CONF"
else
    echo "unlock_time = 900" >> "$FAILLOCK_CONF"
fi

echo "Account lockout set to 3 failed attempts with 15 minute unlock time."
