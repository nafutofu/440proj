# simulate_worm.py
import os
import time

subnet = "192.168.15"

print("Simulating worm spreading across subnet...")
for i in range(2, 50):
    ip = f"{subnet}.{i}"
    print(f"[📡] Probing {ip}...")
    os.system(f"ping -c 1 -W 1 {ip} > /dev/null 2>&1")
    time.sleep(0.1)
    
    
