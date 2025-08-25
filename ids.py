# Clean Intrusion Detection System (IDS) using Scapy
# Captures ICMP, TCP, and UDP packets in real-time
# Ignores non-IP packets to prevent warnings

from scapy.all import sniff, IP, TCP, UDP, ICMP
import os
from datetime import datetime

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

def packet_handler(packet):
    """Process each packet: log ICMP, TCP, UDP; ignore non-IP packets"""
    if not packet.haslayer(IP):
        return  # skip non-IP packets to prevent warnings

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_msg = f"[{timestamp}] "

    if packet.haslayer(ICMP):
        log_msg += f"ICMP Packet: {packet[IP].src} -> {packet[IP].dst}"
    elif packet.haslayer(TCP):
        log_msg += f"TCP Packet: {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport}"
    elif packet.haslayer(UDP):
        log_msg += f"UDP Packet: {packet[IP].src}:{packet[UDP].sport} -> {packet[IP].dst}:{packet[UDP].dport}"
    else:
        return  # skip other packet types

    print(log_msg)
    with open(get_log_file(), "a") as f:
        f.write(log_msg + "\n")

# -------------------------------
# Start sniffing continuously
# -------------------------------
print("Starting Clean Scapy IDS... Press Ctrl+C to stop.")
sniff(prn=packet_handler, store=False)
