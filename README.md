# Overview

This project started as a basic Intrusion Detection System (IDS) built in Python using the Scapy library. The original IDS monitored network traffic and logged potential suspicious activities, such as unusual UDP packets or ICMP packets (like pings). It demonstrated how packet sniffing and analysis can be used in cybersecurity to detect anomalies in network traffic.

The enhanced version builds on this foundation by adding stateful tracking, rule-based detection, severity alerts, JSON logging, and a live CLI dashboard. These improvements make the IDS more practical, informative, and ready for real-world demonstration.

## Features

<ins>Original Features</ins>

- Packet Capture: Uses Scapy to sniff live network packets directly from the network interface.
- Protocol Analysis: Captures and inspects TCP and UDP packets.
- Logs All Findings: Every detected packet is written to a daily log file in the logs/ directory, named with the current date (e.g., ids_log_2025-08-25.txt).
- Alerts: Provides warnings in the terminal when suspicious traffic (e.g., unusual UDP packets or ICMP pings) is detected.

<ins>Enhancements / What’s New</ins>

- Stateful Detection: Tracks connections and packet activity per IP over a configurable time window.
- Rule-Based Alerts with Severity Levels:
    - [HIGH] Port Scan
    - [MEDIUM] Traffic Spike
    - [LOW] ICMP Flood
- Alert Cooldown: Prevents repeated alerts from the same IP within a configurable time frame.
- JSON Logging: Each packet and alert is logged as a structured JSON object for SIEM-ready integration.
- CLI Dashboard: Live terminal-based dashboard showing:
    - Active IPs on the network
    - Alerts triggered
    - Top talker by packet activity
 
⚠️ Note: Thresholds for port scans, traffic spikes, and ICMP floods have been set lower than real-world values to make testing and demonstrations easier.

## Code Explanation

The script imports Scapy’s sniffing API and protocol layers—specifically sniff plus the IP, TCP, UDP, and ICMP layers—to decode packets as they arrive. It also imports os to manage the filesystem (creating a logs/ directory if it doesn’t exist) and datetime to timestamp each event and to build a per-day filename (e.g., logs/logs_YYYY-MM-DD.txt). At startup, the program ensures the logs/ folder exists, then defines a small helper that returns the current day’s log file path, guaranteeing that every run on a given day appends to the same file. The packet handler runs for every captured frame: it first checks that the packet actually contains an IP layer (ignoring non-IP traffic to avoid warnings and clutter), then determines whether it’s ICMP, TCP, or UDP, and formats a single line that includes a precise timestamp, the source/destination IPs, and (for TCP/UDP) the source/destination ports. That line is printed immediately to the terminal for real-time visibility and appended to the day’s log file for persistence. Finally, the program calls Scapy’s sniffer with a callback pointing to that handler and store=False so packets aren’t kept in memory, letting the IDS run continuously and efficiently until you stop it with Ctrl+C.

The enhanced IDS maintains the original packet sniffing and logging logic, while adding a detection layer:

1. Stateful Trackers: Maintain recent packet and connection information per IP for real-time analysis.
2. Detection Functions: Analyze packet patterns to identify port scans, traffic spikes, and ICMP floods, assigning severity levels.
3. Alert Management: Alerts are throttled using a cooldown per IP to avoid spam.
4. JSON Logs: All packet events and alerts are recorded in JSON format in logs/ for easy integration with monitoring tools.
5. CLI Dashboard: Provides an at-a-glance view of network activity, active IPs, top talkers, and alert summaries.
