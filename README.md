📖 Project Description 
This project is a Python-based Network Packet Sniffer and Intrusion Alert System designed for cybersecurity learning and SOC operations training.
It monitors live network traffic, logs packet metadata, and detects malicious behavior such as port scans and DoS-like network bursts.

The system functions similarly to a lightweight IDS (Intrusion Detection System), helping understand core concepts of network monitoring, cybersecurity analytics, packet inspection, and alerting.

🎯 Objectives
Capture live network packets

Extract meaningful packet metadata

Store traffic logs for investigation

Detect network anomalies

Trigger real-time alerts

Build practical cybersecurity & networking skills

🧬 How It Works
Component	Purpose
Packet Sniffer	Captures raw packets using Scapy
Parser	Extracts IP, Ports, Protocol, Size
DB Logger	Saves data into SQLite database
Alert Engine	Detects port-scan & DoS activity
CLI Output	Shows live packet stream + alerts

💡 Use Cases
SOC analyst training

Cybersecurity student project

Packet analysis lab exercise

Intrusion detection research prototype

Ethical hacking labs

🛠️ Installation
bash
Copy code
sudo apt update
sudo apt install python3 python3-pip sqlite3 -y
pip3 install scapy
▶️ Run the Tool
bash
Copy code
sudo python3 sniffer.py
📊 Sample Output
nginx
Copy code
Starting sniffer...
Sniffer ready — capturing on all interfaces
[PACKET] 192.168.0.10:443 → 10.0.2.15:51832 | TCP | 110 bytes
ALERT [PortScan-Suspected] — Source: 127.0.0.1 — Scanned 5 ports in 3 seconds
📂 Database Schema
Table: packets

Field	Type
id	Integer (PK)
ts	Timestamp
src_ip	Text
dst_ip	Text
src_port	Integer
dst_port	Integer
protocol	Text
size	Integer

Table: alerts

Field	Type
id	Integer (PK)
ts	Timestamp
src_ip	Text
alert_type	Text
details	Text

✅ Testing Scenarios
Command	Purpose
ping -c 4 google.com	Test normal ICMP traffic
sudo nmap -sS -p1-200 127.0.0.1	Test port-scan detection
sudo ping -f -c 300 127.0.0.1	Test DoS-like burst
sudo hping3 --scan 1-200 -S 127.0.0.1	High-volume SYN traffic

🚧 Future Enhancements
Web dashboard (Flask / Streamlit)

Email / SMS alerting

PCAP file import support

Threat intelligence API integration

ML-based anomaly detection

Export logs to ELK / Splunk

📜 License
MIT License — free for study and research use.

