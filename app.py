from flask import Flask, render_template, jsonify
from scapy.all import sniff, IP
from threading import Thread
from logger import log_alert

app = Flask(__name__)
alerts = []

def packet_monitor(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        if ip_src.startswith("192.168"):
            alert = f"Suspicious packet: {ip_src} -> {ip_dst} | Protocol: {protocol}"
            alerts.append(alert)
            log_alert(alert)
            print(alert)

@app.route('/')
def index():
    return render_template('index.html', alerts=alerts)

@app.route('/alerts')
def get_alerts():
    return jsonify(alerts)

def start_sniffing():
    sniff(filter="ip", prn=packet_monitor, store=0)

if __name__ == "__main__":
    thread = Thread(target=start_sniffing)
    thread.start()
    app.run(debug=True)

