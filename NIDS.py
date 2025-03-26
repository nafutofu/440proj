from scapy.all import sniff, IP, TCP, Raw
import time
from collections import defaultdict
import logging

INTERFACES = ["Ethernet 2", "Ethernet 3"]

logging.basicConfig(filename="ids_log.txt", level=logging.INFO, format="%(asctime)s - %(message)s")

# Constants
TIME_WINDOW = 5  # seconds
DOS_THRESHOLD = 200  # Packets in TIME_WINDOW to trigger DoS
PORT_SCAN_THRESHOLD = 10  # Unique ports to trigger Port Scan
SYN_FLOOD_THRESHOLD = 100  # SYN packets to 1 port in TIME_WINDOW
ALERT_RESET_TIME = 10  # Cooldown before detecting the same attack again
MALWARE_SIGNATURES = [b"malware_pattern1", b"exploit_code"]  # Example signatures
WORM_TIME_WINDOW = 10  # seconds
WORM_THRESHOLD = 10    # unique IPs contacted

# Trackers
worm_tracker = defaultdict(list)  # {src_ip: [(timestamp, dst_ip)]}
packet_count = defaultdict(list)  # Tracks packets per source IP
port_scan_tracker = defaultdict(set)  # Tracks unique ports per source IP
syn_flood_tracker = defaultdict(list)  # Tracks SYN packets per IP & Port
recent_alerts = {}  # Stores alerts & timestamps to avoid duplicates

def detect_attack(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport if packet.haslayer(TCP) else "Unknown"
        current_time = time.time()

        # Reset alerts older than ALERT_RESET_TIME
        for alert in list(recent_alerts.keys()):
            if current_time - recent_alerts[alert] > ALERT_RESET_TIME:
                del recent_alerts[alert]

        # SYN Flood Detection (High SYN requests to one port)
        if packet.haslayer(TCP) and packet[TCP].flags == "S":
            syn_flood_tracker[src_ip].append((current_time, dst_port))
            syn_flood_tracker[src_ip] = [p for p in syn_flood_tracker[src_ip] if current_time - p[0] < TIME_WINDOW]

            ports_hit = [p[1] for p in syn_flood_tracker[src_ip]]

            if len(ports_hit) > SYN_FLOOD_THRESHOLD and len(set(ports_hit)) == 1:
                if (src_ip, "SYN_FLOOD") in recent_alerts:
                    return  # Prevent duplicate alerts

                recent_alerts[(src_ip, "SYN_FLOOD")] = current_time
                alert_msg = f"ALERT: SYN Flood detected on port {dst_port} from {src_ip}!"
                print(alert_msg)
                logging.info(alert_msg)
                return

        # DoS Detection
        if (src_ip, "SYN_FLOOD") not in recent_alerts:
            packet_count[src_ip].append(current_time)
            packet_count[src_ip] = [t for t in packet_count[src_ip] if current_time - t < TIME_WINDOW]

            if len(packet_count[src_ip]) > DOS_THRESHOLD and (src_ip, "DOS_ATTACK") not in recent_alerts:
                recent_alerts[(src_ip, "DOS_ATTACK")] = current_time
                alert_msg = f"ALERT: DoS attack detected from {src_ip}!"
                print(alert_msg)
                logging.info(alert_msg)

        # Port Scan
        if packet.haslayer(TCP):
            port_scan_tracker[src_ip].add(dst_port)
            if len(port_scan_tracker[src_ip]) > PORT_SCAN_THRESHOLD and (src_ip, "PORT_SCAN") not in recent_alerts:
                recent_alerts[(src_ip, "PORT_SCAN")] = current_time
                alert_msg = f"ALERT: Port scanning detected from {src_ip}!"
                print(alert_msg)
                logging.info(alert_msg)

        # Malware Signature Detection
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            for signature in MALWARE_SIGNATURES:
                if signature in payload and (src_ip, "MALWARE") not in recent_alerts:
                    recent_alerts[(src_ip, "MALWARE")] = current_time
                    alert_msg = f"MALWARE ALERT! Packet from {src_ip} contains a known exploit signature!"
                    print(alert_msg)
                    logging.info(alert_msg)
        
        # Worm Detection
        
        worm_tracker[src_ip].append((current_time, dst_ip)) # keep track of possible ips
        
        worm_tracker[src_ip] = [ # keep only entries within the time window
            (t, d) for (t, d) in worm_tracker[src_ip]
            if current_time - t < WORM_TIME_WINDOW
        ]
        
        unique_dsts = set([d for (t, d) in worm_tracker[src_ip]]) # count unique destination IPs

        if len(unique_dsts) >= WORM_THRESHOLD:
            print(f"ALERT: Worm-like behavior detected from {src_ip} — contacted {len(unique_dsts)} hosts!")
        
        

print("IDS is running... Monitoring traffic.")
for interface in INTERFACES:
    sniff(iface=interface, prn=detect_attack, store=0)
