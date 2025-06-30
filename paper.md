---
title: 'NetSec-MiniTools: Lightweight Python Scripts for Network and Log-Based Intrusion Detection'
tags:
  - Python
  - Cybersecurity
  - Honeypot
  - Network Monitoring
  - Intrusion Detection
authors:
  - name: Leigha Ifiyemi
    affiliation: 1
    orcid: 0000-0000-0000-0000  # <== replace with your ORCID
affiliations:
  - name: ISEP Paris
    index: 1
date: 2025-07-01
---

# Summary

NetSec-MiniTools is a suite of lightweight Python-based tools for real-time and post-event intrusion detection. The tools include a passive honeypot for capturing IPs and banners, a real-time packet sniffer with risk scoring, and a log-based port scan detector. Designed for practical use, labs, and beginner-friendly setups, it helps security students and analysts monitor early-stage attacks.

# Statement of Need

While large-scale intrusion detection systems are resource-intensive, there's a gap for beginner-friendly tools that are transparent and fast to deploy. This toolkit bridges that gap by offering small, auditable scripts that still simulate real-world detection behaviors like honeypots, portscan detection, and suspicious flag scoring.

# Functionality

- `log_ip_sniffer.py`: Passive TCP honeypot that logs timestamps, banners, and source IPs.
- `scapy_realtime_monitor.py`: Live packet sniffer with scoring based on suspicious flags and destination ports.
- `detect_portscan.py`: Identifies repeated connections from the same IP in logs, simulating a lightweight NIDS.

# Usage

```bash
python tools/log_ip_sniffer.py
python tools/scapy_realtime_monitor.py
python tools/detect_portscan.py
