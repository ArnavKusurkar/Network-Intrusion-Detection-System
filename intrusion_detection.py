from scapy.all import sniff, IP, TCP
from collections import defaultdict

connection_count = defaultdict(int)

def detect_port_scan(packet):
    if IP in packet and TCP in packet:
        ip_src = packet[IP].src
        port_dst = packet[TCP].dport
        
        connection_count[(ip_src, port_dst)] += 1
        
        if connection_count[(ip_src, port_dst)] > 10:
            print(f"Potential port scan detected from {ip_src} on port {port_dst}")

sniff(filter="tcp", prn=detect_port_scan, store=0)

