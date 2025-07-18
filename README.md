**AI-Powered Intrusion Detection System (IDS)**
Overview
This project implements an AI-powered Intrusion Detection System (IDS) that leverages machine learning to identify anomalous network traffic, helping to detect potential cyber threats in real-time. The system uses the IsolationForest algorithm from scikit-learn for anomaly detection and Scapy for network packet sniffing. It is designed for educational purposes or small-scale network monitoring.

**Features**

Real-Time Packet Analysis: Captures and analyzes network packets using Scapy.
AI-Based Anomaly Detection: Uses Isolation Forest to identify unusual traffic patterns.
Threaded Execution: Non-blocking packet sniffing for continuous monitoring.
Logging: Outputs alerts for detected anomalies, including source IP addresses.

**Requirements**

Python: 3.8 or higher
Operating System: Linux (e.g., Kali, Ubuntu) recommended; requires root privileges for packet sniffing.

**Dependencies:**

scikit-learn (1.7.0 or higher)
scapy (2.6.1 or higher)
numpy (2.3.1 or higher)


**System Libraries:**
libpcap-dev (for Scapy packet capture)



**Installation**

Set Up a Virtual Environment (recommended):python3 -m venv venv
source venv/bin/activate


Install Python Dependencies:pip install scikit-learn scapy numpy


**Install System Libraries (on Linux)**: sudo apt-get update
                                        sudo apt-get install libpcap-dev


**Verify Installation:** pip list

Ensure scikit-learn, scapy, and numpy are listed.
**
Usage**

**Update Network Interface:**
**Find your active network interface:** ip link

**
Edit ips.py to set the correct interface (e.g., replace eth0 with wlan0):** def start_ids(interface="wlan0", duration=60):




**Run the Script:**

**Activate the virtual environment:** source venv/bin/activate


**Run with sudo to allow packet sniffing**: sudo venv/bin/python3 ips.py


The script will sniff packets for 60 seconds (configurable) and log potential anomalies.


**Monitor Output:**

Check terminal logs for messages like:
Starting packet sniffing on <interface> for 60 seconds...
**Anomaly detected:** <features>


Anomalies indicate potential threats (e.g., unusual packet patterns).



**Configuration**

**Interface:** Set the interface parameter in start_ids to match your network interface (e.g., wlan0).
**Duration:** Adjust the duration parameter in start_ids to control sniffing time (default: 60 seconds).
**Contamination:** Modify the contamination parameter in IsolationForest (default: 0.1) to adjust anomaly sensitivity.

**Example**

source venv/bin/activate
sudo venv/bin/python3 ips.py

**Sample output:**
2025-07-18 10:23:45,123 - INFO - Starting packet sniffing on wlan0 for 60 seconds...
2025-07-18 10:23:50,456 - WARNING - Anomaly detected: [1500, 6, 12345, 80, 64]
2025-07-18 10:23:50,457 - WARNING - Potential threat from 192.168.1.100

**Notes**

**Permissions:** Requires root privileges (sudo) for Scapy to capture packets.
Network Traffic: Ensure your network has active traffic (e.g., run ping 8.8.8.8) for meaningful results.
**Scalability:** This is a prototype for educational use. For production, consider integrating with tools like Suricata or using a database for logs.
Tuning: Adjust contamination (e.g., 0.05 for higher sensitivity) to reduce false positives/negatives.
**Kali Linux:** Ensure no firewall blocks packet sniffing:sudo ufw status
sudo ufw disable  # If needed, for testing



**Troubleshooting**

**ModuleNotFoundError:** No module named 'sklearn':
Ensure you’re using the virtual environment’s Python:sudo venv/bin/python3 ips.py


**Reinstall dependencies:** pip install scikit-learn scapy numpy




**No Packet Capture:**
Verify the correct network interface with ip link.
Ensure libpcap-dev is installed.


**Errors During Execution:**
Check Python version (python3 --version); requires 3.8+.
Share error logs for further assistance.



**This project is for educational purposes** 


Feel free to submit issues or pull requests for enhancements, such as adding new features or improving the AI model.
