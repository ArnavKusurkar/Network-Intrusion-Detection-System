# Network Intrusion Detection System (NIDS)

# Ethical Considerations #
PLEASE USE THIS FOR ETHICAL REASONS ONLY. If used for any kind of malpractices, the author cannot be held responsible. This tool is intended solely for educational purposes and authorized testing on networks you own or have explicit permission to monitor. Unauthorized use of network monitoring tools is illegal and unethical. Always ensure you are compliant with all applicable laws and guidelines.

## Overview
This project is a custom Network Intrusion Detection System (NIDS) built in Python using Scapy and Flask. It monitors network traffic in real-time, detects suspicious activities, and provides alerts via a web dashboard.

## Features
- Real-time packet capturing and monitoring.
- Signature-based detection for common network attacks.
- Anomaly detection for unusual bandwidth usage.
- Web dashboard for viewing alerts.
- Logging of detected incidents.

## Setup Instructions

**After starting the server open your web browser and navigate to http://127.0.0.1:5000 to view real-time alerts and monitor network activities.**
*To start the server follow the procedure given below*
 **Clone the repository**:
   ```bash
   git clone https://github.com/ArnavKusurkar/Network-Intrusion-Detection-System.git
   cd network-intrusion-detection-system
   python3 -m venv env
   source env/bin/activate
   pip install -r requirements.txt
   python app.py

