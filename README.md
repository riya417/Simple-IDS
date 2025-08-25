# Overview

This project is a basic Intrusion Detection System (IDS) built in Python using the Scapy library. The IDS monitors network traffic and logs potential suspicious activities, such as unusual UDP packets or ICMP packets (like pings). It demonstrates how packet sniffing and analysis can be used in cybersecurity to detect anomalies in network traffic.

## Features

- Packet Capture: Uses Scapy to sniff live network packets directly from the network interface.

- Protocol Analysis: Captures and inspects both TCP and UDP packets.

- Logs All Findings: Every detected packet is written to a daily log file in the logs/ directory, named with the current date (e.g., ids_log_2025-08-25.txt).

- Alerts: Provides warnings in the terminal when suspicious traffic (e.g., unusual UDP packets or ICMP pings) is detected.

## Code Explanation

The script imports Scapy’s sniffing API and protocol layers—specifically sniff plus the IP, TCP, UDP, and ICMP layers—to decode packets as they arrive. It also imports os to manage the filesystem (creating a logs/ directory if it doesn’t exist) and datetime to timestamp each event and to build a per-day filename (e.g., logs/logs_YYYY-MM-DD.txt). At startup, the program ensures the logs/ folder exists, then defines a small helper that returns the current day’s log file path, guaranteeing that every run on a given day appends to the same file. The packet handler runs for every captured frame: it first checks that the packet actually contains an IP layer (ignoring non-IP traffic to avoid warnings and clutter), then determines whether it’s ICMP, TCP, or UDP, and formats a single line that includes a precise timestamp, the source/destination IPs, and (for TCP/UDP) the source/destination ports. That line is printed immediately to the terminal for real-time visibility and appended to the day’s log file for persistence. Finally, the program calls Scapy’s sniffer with a callback pointing to that handler and store=False so packets aren’t kept in memory, letting the IDS run continuously and efficiently until you stop it with Ctrl+C.
