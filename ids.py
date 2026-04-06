# Enhanced Intrusion Detection System (IDS) with Scapy
# Rule-based, severity alerts, cooldowns, JSON logging, CLI dashboard

from scapy.all import sniff, IP, TCP, UDP, ICMP
import os
import time
import json
from datetime import datetime
from collections import defaultdict

# -------------------------------
# Setup logs folder
# -------------------------------
log_dir = "logs"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

def get_log_file():
    """Return the log file path for the current date"""
    date_str = datetime.now().strftime("%Y-%m-%d")
    return os.path.join(log_dir, f"logs_{date_str}.txt")

# -------------------------------
# Configuration
# -------------------------------
PORT_SCAN_THRESHOLD = 3       # ports in TIME_WINDOW
TRAFFIC_THRESHOLD = 5         # packets in TIME_WINDOW
ICMP_THRESHOLD = 10           # ICMP packets in TIME_WINDOW
TIME_WINDOW = 10              # seconds
ALERT_COOLDOWN = 30           # seconds per IP

# -------------------------------
# Stateful Trackers
# -------------------------------
connection_tracker = defaultdict(list)  # TCP/UDP port activity
traffic_tracker = defaultdict(list)     # All packet timestamps
icmp_tracker = defaultdict(list)        # ICMP timestamps
last_alert_time = defaultdict(lambda: 0) # cooldown tracker

# -------------------------------
# Detection & Severity Logic
# -------------------------------
def detect_threats(src_ip, protocol, dport=None):
    current_time = time.time()
    alert_msg = None
    severity = "LOW"

    # -------------------
    # Port Scan Detection (HIGH)
    # -------------------
    if dport is not None:
        connection_tracker[src_ip].append((dport, current_time))
        # Keep only recent ports
        connection_tracker[src_ip] = [
            (port, t) for port, t in connection_tracker[src_ip]
            if current_time - t <= TIME_WINDOW
        ]
        # Count unique numeric ports only
        unique_ports = set(port for port, _ in connection_tracker[src_ip] if isinstance(port, int))
        if len(unique_ports) > PORT_SCAN_THRESHOLD:
            alert_msg = f"[HIGH] ALERT: Possible Port Scan from {src_ip}"
            severity = "HIGH"

    # -------------------
    # Traffic Spike Detection (MEDIUM)
    # -------------------
    traffic_tracker[src_ip].append(current_time)
    traffic_tracker[src_ip] = [
        t for t in traffic_tracker[src_ip] if current_time - t <= TIME_WINDOW
    ]
    if len(traffic_tracker[src_ip]) > TRAFFIC_THRESHOLD and severity != "HIGH":
        alert_msg = f"[MEDIUM] ALERT: Traffic Spike from {src_ip}"
        severity = "MEDIUM"

    # -------------------
    # ICMP Flood Detection (LOW)
    # -------------------
    if protocol == "ICMP" and severity not in ["HIGH", "MEDIUM"]:
        icmp_tracker[src_ip].append(current_time)
        icmp_tracker[src_ip] = [
            t for t in icmp_tracker[src_ip] if current_time - t <= TIME_WINDOW
        ]
        if len(icmp_tracker[src_ip]) > ICMP_THRESHOLD:
            alert_msg = f"[LOW] ALERT: ICMP Flood from {src_ip}"
            severity = "LOW"

    # -------------------
    # Check cooldown
    # -------------------
    if alert_msg:
        if current_time - last_alert_time[src_ip] >= ALERT_COOLDOWN:
            last_alert_time[src_ip] = current_time
            return alert_msg, severity
        else:
            return None, None
    return None, None

# -------------------------------
# Packet Handler
# -------------------------------
def packet_handler(packet):
    if not packet.haslayer(IP):
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src = packet[IP].src
    dst = packet[IP].dst
    log_entry = {
        "timestamp": timestamp,
        "src": src,
        "dst": dst,
        "protocol": None,
        "sport": None,
        "dport": None,
        "alert": None,
        "severity": None
    }

    alert_msg = None
    severity = None

    if packet.haslayer(ICMP):
        log_entry["protocol"] = "ICMP"
        alert_msg, severity = detect_threats(src, "ICMP")

    elif packet.haslayer(TCP):
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        log_entry.update({"protocol": "TCP", "sport": sport, "dport": dport})
        alert_msg, severity = detect_threats(src, "TCP", dport)

    elif packet.haslayer(UDP):
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        log_entry.update({"protocol": "UDP", "sport": sport, "dport": dport})
        alert_msg, severity = detect_threats(src, "UDP", dport)

    # -------------------------------
    # Print & Log
    # -------------------------------
    print(f"[{timestamp}] {log_entry['protocol']} Packet: {src} -> {dst}", end="")
    if log_entry["sport"] and log_entry["dport"]:
        print(f" | Ports {log_entry['sport']} -> {log_entry['dport']}", end="")
    print()

    if alert_msg:
        log_entry["alert"] = alert_msg
        log_entry["severity"] = severity
        print(alert_msg)

    # -------------------------------
    # Write JSON log
    # -------------------------------
    with open(get_log_file(), "a") as f:
        f.write(json.dumps(log_entry) + "\n")

# -------------------------------
# CLI Dashboard
# -------------------------------
def dashboard():
    os.system('cls' if os.name == 'nt' else 'clear')
    print("=== IDS CLI Dashboard ===")
    print(f"Active IPs: {len(connection_tracker)}")
    total_alerts = sum(1 for ip in last_alert_time if last_alert_time[ip] > 0)
    print(f"Alerts Triggered: {total_alerts}")
    top_talker = max(connection_tracker, key=lambda ip: len(connection_tracker[ip]), default="N/A")
    print(f"Top Talker: {top_talker}")
    print("=========================")

# -------------------------------
# Sniffing Loop with Dashboard
# -------------------------------
def start_ids():
    print("Starting Enhanced Scapy IDS... Press Ctrl+C to stop.")
    try:
        while True:
            sniff(timeout=5, prn=packet_handler, store=False)
            dashboard()
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping IDS...")

# -------------------------------
# Entry Point
# -------------------------------
if __name__ == "__main__":
    start_ids()
