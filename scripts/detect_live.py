# detect_live.py (Background Script)
from scapy.all import sniff, DNS, IP
import pandas as pd
import joblib
import os
from datetime import datetime
import traceback

# Load trained model
model = joblib.load("models/trained_model.pkl")

# Log file path
LOG_PATH = "logs/detection_log.txt"
os.makedirs("logs", exist_ok=True)

def log_message(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_PATH, "a", encoding="utf-8") as f:  # ✅ Safe encoding
        f.write(f"[{timestamp}] {msg}\n")

def detect_packet(pkt):
    if DNS in pkt and IP in pkt:
        try:
            ip_layer = pkt[IP]
            dns_layer = pkt[DNS]

            pkt_len = len(pkt)
            qtype = dns_layer.qd.qtype if dns_layer.qr == 0 else 0
            ttl = ip_layer.ttl
            is_response = dns_layer.qr
            ancount = dns_layer.ancount
            likely_spoofed_response = 1 if is_response == 1 and ttl <= 64 and ancount == 0 and pkt_len <= 80 else 0

            # Construct feature vector
            features = pd.DataFrame([[pkt_len, qtype, is_response, ttl, ancount, likely_spoofed_response]],
                columns=["packet_size", "query_type", "is_response", "ttl", "ancount", "likely_spoofed_response"])

            # Prediction
            proba = model.predict_proba(features)[0][1]
            prediction = model.predict(features)[0]

            # Format message
            msg = f"Src: {ip_layer.src} -> Dst: {ip_layer.dst} | QTYPE={qtype}, Size={pkt_len}, TTL={ttl}, ancount={ancount}, Confidence={proba:.2f}"
            if qtype == 255 or (proba >= 0.95 and prediction == 1):
                log_message("[ATTACK] " + msg)
            else:
                log_message("[NORMAL] " + msg)

        except Exception as e:
            log_message(f"[ERROR] Failed to process packet: {e}")
            log_message(traceback.format_exc())

# Main entry
print("[*] DNS Monitoring started on interface: Wi-Fi...")
try:
    sniff(filter="udp port 53", prn=detect_packet, iface="Wi-Fi", store=0)
except Exception as e:
    print(f"[!] Error: {e}")
