
from scapy.all import sniff, IP, TCP, UDP
import sqlite3
from datetime import datetime

# Initialize DB
conn = sqlite3.connect("packet_logs.db")
cursor = conn.cursor()
cursor.execute("CREATE TABLE IF NOT EXISTS packets (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, src_ip TEXT, dst_ip TEXT, protocol TEXT, sport TEXT, dport TEXT)")
conn.commit()

def log_packet(timestamp, src, dst, proto, sport, dport):
    cursor.execute("INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, sport, dport) VALUES (?, ?, ?, ?, ?, ?)",
                   (timestamp, src, dst, proto, sport, dport))
    conn.commit()

def process_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src = ip_layer.src
        dst = ip_layer.dst
        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            protocol = "TCP"
        elif packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            protocol = "UDP"
        else:
            sport = dport = "-"
            protocol = "Other"
        print(f"[{protocol}] {src}:{sport} -> {dst}:{dport}")
        log_packet(timestamp, src, dst, protocol, str(sport), str(dport))

print("🔍 Starting packet sniffing...")
sniff(prn=process_packet, store=False)
