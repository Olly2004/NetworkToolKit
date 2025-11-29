#NetworkToolKit
A lightweight Python toolkit for packet sniffing, protocol analysis, and ARP-based network security testing.

NetworkToolKit is a GUI-based networking and cybersecurity toolkit built with **Python**, **Tkinter**, and **Scapy**.  
It provides real-time packet capture, analysis, filtering, DNS/SNI inspection, and ARP spoofing/detection features — designed for learning, testing, and exploring network behaviour in controlled environments.

---

## Features

### **Real Time Packet Sniffer**
- Capture live network traffic using Scapy  
- Protocol filtering (TCP, UDP, ICMP, ARP, or ALL)
- Victim-only mode (filter packets by source/destination IP)
- Batch/offline mode for analysing `.pcap` files
- Real-time streaming into a GUI console

### **DNS & SNI Sniffers**
- Extract DNS queries and responses  
- Extract TLS SNI (Server Name Indication) fields  
- Useful for visibility into encrypted and unencrypted traffic patterns  

### **ARP Tools**
- ARP spoofing module (with automatic ARP restoration)
- Detect suspicious ARP responses  
- Helpful for demonstrating MITM techniques in test environments  
- Includes safeguards & warnings to prevent misuse

### **GUI**
- Built with Tkinter  
- Multi-page layout (packet sniffer, DNS/SNI tools, ARP tools)  
- Threaded subprocess system to keep UI responsive  
- Supports interface selection and background process control

---

## Things Used
- **Python 3**
- **Scapy**
- **Tkinter**
- **Threading & Subprocess**
- **Linux networking utilities (iptables, sysctl)**

---

## Installation

```bash
git clone https://github.com/Olly2004/NetworkToolKit
cd NetworkToolKit
pip install -r requirements.txt
