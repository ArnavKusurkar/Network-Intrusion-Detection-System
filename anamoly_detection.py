from scapy.all import sniff, IP
from collections import defaultdict

bandwidth_usage = defaultdict(int)

def detect_bandwidth_anomaly(packet):
    if IP in packet:
        ip_src = packet[IP].src
        packet_size = len(packet)

        bandwidth_usage[ip_src] += packet_size
        
        if bandwidth_usage[ip_src] > 1000000:  
            print(f"Bandwidth anomaly detected from {ip_src} with {bandwidth_usage[ip_src]} bytes in usage")

sniff(filter="ip", prn=detect_bandwidth_anomaly, store=0)

