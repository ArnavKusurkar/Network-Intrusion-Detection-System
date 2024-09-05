from scapy.all import sniff, IP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        print(f"Packet: {ip_src} -> {ip_dst} | Protocol: {protocol}")
sniff(filter="ip", prn=packet_callback, store=0)
