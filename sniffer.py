#!/usr/bin/env python3
"""
sniffer.py
Network Packet Sniffer + SQLite logging + simple anomaly detection
Run with: sudo python3 sniffer.py
"""

import time
import sqlite3
import logging
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP

# ---------------------------
# CONFIG
# ---------------------------
DB_FILE = "packets.db"
LOG_FILE = "sniffer.log"

# Detection thresholds (tweak as needed)
WINDOW_SECONDS = 10            # sliding window in seconds
PORTSCAN_PORT_THRESHOLD = 20   # distinct destination ports in WINDOW considered a port scan
DOS_PACKET_THRESHOLD = 200   # packets from same src in WINDOW considered DoS-ish

# ---------------------------
# Logging
# ---------------------------
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s"
)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
logging.getLogger().addHandler(console)

logging.info("Starting sniffer...")

# ---------------------------
# Database setup
# ---------------------------
conn = sqlite3.connect(DB_FILE, check_same_thread=False)
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL,
    src_ip TEXT,
    src_port TEXT,
    dst_ip TEXT,
    dst_port TEXT,
    protocol TEXT,
    size INTEGER
)
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL,
    src_ip TEXT,
    alert_type TEXT,
    details TEXT
)
""")
conn.commit()

# ---------------------------
# In-memory structures for detection
# ---------------------------
# For packet count per source: map src_ip -> deque of timestamps
packet_times = defaultdict(deque)

# For port-scan detection: map (src_ip) -> dict(dst_ip -> set of (dst_port, timestamp))
port_activity = defaultdict(lambda: defaultdict(lambda: deque()))

# Helper to cleanup old timestamps from deque
def cleanup_deque(dq, window):
    now = time.time()
    while dq and dq[0] < now - window:
        dq.popleft()

# ---------------------------
# Detection functions
# ---------------------------
def check_dos(src_ip):
    dq = packet_times[src_ip]
    cleanup_deque(dq, WINDOW_SECONDS)
    count = len(dq)
    if count >= DOS_PACKET_THRESHOLD:
        detail = f"High packet rate: {count} pkts in last {WINDOW_SECONDS}s"
        register_alert(src_ip, "DoS-Suspected", detail)
        # clear deque to avoid repeated alerts immediately
        dq.clear()

def check_portscan(src_ip):
    now = time.time()
    # collect distinct dst_ports across dst_ips within window
    dst_ports_set = set()
    for dst_ip, deque_list in list(port_activity[src_ip].items()):
        # each element in deque_list is (dst_port, ts)
        # remove old entries
        while deque_list and deque_list[0][1] < now - WINDOW_SECONDS:
            deque_list.popleft()
        for port, ts in deque_list:
            dst_ports_set.add(port)
    if len(dst_ports_set) >= PORTSCAN_PORT_THRESHOLD:
        detail = f"Scanned {len(dst_ports_set)} distinct dst ports in last {WINDOW_SECONDS}s"
        register_alert(src_ip, "PortScan-Suspected", detail)
        # clear activity to reduce duplicate alerts
        port_activity[src_ip].clear()

def register_alert(src_ip, alert_type, details):
    ts = time.time()
    cur.execute("INSERT INTO alerts (ts, src_ip, alert_type, details) VALUES (?, ?, ?, ?)",
                (ts, src_ip, alert_type, details))
    conn.commit()
    logging.warning(f"ALERT [{alert_type}] from {src_ip} — {details}")
    # Optionally: call send_email_alert(...) here — stub provided below

# ---------------------------
# Packet callback
# ---------------------------
def packet_callback(pkt):
    ts = time.time()
    proto = "Other"
    src_ip = dst_ip = src_port = dst_port = "N/A"
    size = len(pkt)

    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto_num = pkt[IP].proto
        if proto_num == 6:
            proto = "TCP"
        elif proto_num == 17:
            proto = "UDP"
        else:
            proto = str(proto_num)

        if TCP in pkt:
            src_port = str(pkt[TCP].sport)
            dst_port = str(pkt[TCP].dport)
            flags = pkt[TCP].flags
        elif UDP in pkt:
            src_port = str(pkt[UDP].sport)
            dst_port = str(pkt[UDP].dport)
            flags = None
        else:
            flags = None

    # Insert into DB
    try:
        cur.execute("INSERT INTO packets (ts, src_ip, src_port, dst_ip, dst_port, protocol, size) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (ts, src_ip, src_port, dst_ip, dst_port, proto, size))
        conn.commit()
    except Exception as e:
        logging.error(f"DB insert error: {e}")

    # Update detection structures
    # Packet count
    packet_times[src_ip].append(ts)
    cleanup_deque(packet_times[src_ip], WINDOW_SECONDS)

    # Port activity (for TCP/UDP)
    if dst_port != "N/A":
        # store tuple (dst_port, timestamp) in deque per dst_ip
        port_activity[src_ip][dst_ip].append((dst_port, ts))

    # Run quick detections
    check_dos(src_ip)
    check_portscan(src_ip)

    # Print friendly console line
    logging.info(f"[Packet] {src_ip}:{src_port} → {dst_ip}:{dst_port} | {proto} | {size} bytes")

# ---------------------------
# (Optional) Email alert stub
# ---------------------------
# To enable email alerts, implement send_email_alert() and call it inside register_alert.
# Example (Gmail + app password):
#
# import smtplib
# from email.message import EmailMessage
# def send_email_alert(subject, body, to_addr="you@example.com"):
#     msg = EmailMessage()
#     msg.set_content(body)
#     msg["Subject"] = subject
#     msg["From"] = "alertsender@example.com"
#     msg["To"] = to_addr
#     with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
#         smtp.login("you@gmail.com", "APP_PASSWORD")
#         smtp.send_message(msg)
#
# WARNING: store credentials securely if used.

# ---------------------------
# Main sniff loop
# ---------------------------
def main():
    logging.info("Sniffer ready — capturing on all interfaces (CTRL+C to stop)")
    try:
        sniff(prn=packet_callback, store=False)
    except PermissionError:
        logging.error("Permission denied. Run with sudo.")
    except KeyboardInterrupt:
        logging.info("Stopping sniffer (user interrupt).")
    finally:
        conn.close()
        logging.info("DB connection closed. Exiting.")

if __name__ == "__main__":
    main()

