import numpy as np
from sklearn.ensemble import IsolationForest
from scapy.all import sniff, IP, TCP, UDP
import time
import logging
from collections import deque
import threading

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Feature extraction for network packets
def extract_features(packet):
    try:
        features = []
        if IP in packet:
            # Packet length
            features.append(len(packet))
            # Protocol (TCP=6, UDP=17, etc.)
            features.append(packet[IP].proto)
            # Source and destination ports
            if TCP in packet:
                features.append(packet[TCP].sport)
                features.append(packet[TCP].dport)
            elif UDP in packet:
                features.append(packet[UDP].sport)
                features.append(packet[UDP].dport)
            else:
                features.extend([0, 0])  # Default for non-TCP/UDP
            # Time-to-live
            features.append(packet[IP].ttl)
        else:
            # Default values for non-IP packets
            features.extend([0, 0, 0, 0, 0])
        return features
    except Exception as e:
        logging.error(f"Error extracting features: {e}")
        return [0] * 5

# AI-based anomaly detection
class IntrusionDetectionSystem:
    def __init__(self):
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.packet_buffer = deque(maxlen=1000)  # Store recent packet features
        self.training_data = []
        self.is_trained = False
        self.lock = threading.Lock()

    def train_model(self, training_packets):
        logging.info("Training the model...")
        features = [extract_features(pkt) for pkt in training_packets]
        self.training_data.extend(features)
        if len(self.training_data) > 100:  # Minimum data for training
            self.model.fit(self.training_data)
            self.is_trained = True
            logging.info("Model trained successfully.")
        else:
            logging.warning("Insufficient data for training.")

    def detect_anomaly(self, packet):
        with self.lock:
            features = extract_features(packet)
            self.packet_buffer.append(features)
            if not self.is_trained:
                self.training_data.append(features)
                if len(self.training_data) > 100:
                    self.train_model(list(self.packet_buffer))
                return False  # Not trained yet
            prediction = self.model.predict([features])[0]
            if prediction == -1:
                logging.warning(f"Anomaly detected: {features}")
                return True
            return False

    def packet_callback(self, packet):
        if self.detect_anomaly(packet):
            src_ip = packet[IP].src if IP in packet else "Unknown"
            logging.warning(f"Potential threat from {src_ip}")

# Main function to start sniffing and detection
def start_ids(interface="eth0", duration=60):
    ids = IntrusionDetectionSystem()
    logging.info(f"Starting packet sniffing on {interface} for {duration} seconds...")
    try:
        sniff(iface=interface, prn=ids.packet_callback, store=False, timeout=duration)
    except Exception as e:
        logging.error(f"Error during packet sniffing: {e}")

# Run the IDS in a separate thread
def run_ids():
    try:
        interface = "eth0"  # Replace with your network interface
        duration = 60  # Sniffing duration in seconds
        thread = threading.Thread(target=start_ids, args=(interface, duration))
        thread.start()
        thread.join()
    except KeyboardInterrupt:
        logging.info("Shutting down IDS...")
    except Exception as e:
        logging.error(f"Error running IDS: {e}")

if __name__ == "__main__":
    run_ids()