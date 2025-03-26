import os
import time
import psutil

WATCH_FILE = "pc\sensitive.txt"
WATCH_DIR = "pc\Downloads"
SUSPICIOUS_PROCESSES = ["mimikatz.exe"]

last_mod_time = os.path.getmtime(WATCH_FILE)
print(f"[HIDS] Monitoring started...\n")

while True:
    # Monitor file modification
    try:
        new_mod_time = os.path.getmtime(WATCH_FILE)
        if new_mod_time != last_mod_time:
            print(f"ALERT: {WATCH_FILE} was modified!")
            last_mod_time = new_mod_time
    except FileNotFoundError:
        pass

    # Monitor suspicious processes
    for proc in psutil.process_iter(['pid', 'name']):
        pname = proc.info['name']
        if pname and pname.lower() in SUSPICIOUS_PROCESSES:
            print(f"ALERT: Suspicious process running: {pname} (PID: {proc.info['pid']})")

    # Monitor dropped files
    if os.path.exists(WATCH_DIR):
        for f in os.listdir(WATCH_DIR):
            if f.endswith(".exe") or f.endswith(".bat"):
                print(f"ALERT: Suspicious file detected in Downloads: {f}")

    time.sleep(2)  # Poll every 2 seconds
