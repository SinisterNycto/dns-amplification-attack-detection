from scapy.all import sniff, DNS, IP, get_if_list
import pandas as pd
import joblib
import os
import time
import threading
import queue
import logging
import argparse
from collections import defaultdict
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import INTERFACE, PCAP_FILTER, MODEL_PATH
from src.database import save_detection

os.makedirs("logs", exist_ok=True)

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/detection_app.log"),
        logging.StreamHandler()
    ]
)

try:
    model = joblib.load(MODEL_PATH)
    logging.info(f"Loaded ML model from {MODEL_PATH}")
except Exception as e:
    logging.warning(f"Could not load ML model (maybe it needs retraining?): {e}")
    model = None

# Queue for async packet processing
packet_queue = queue.Queue()

def packet_handler(pkt):
    """Callback for scapy sniff to quickly enqueue packets without blocking."""
    if DNS in pkt and IP in pkt:
        packet_queue.put((time.time(), pkt))

def batch_processor():
    """Background worker that aggregates packets in 1-second windows and runs inference."""
    current_window_start = int(time.time())
    
    # Store stats per destination IP
    windows = defaultdict(lambda: {"queries": 0, "responses": 0, "response_size": 0})
    
    while True:
        try:
            # Block until a packet arrives or 0.5s passes
            pkt_time, pkt = packet_queue.get(timeout=0.5)
            
            dst_ip = pkt[IP].dst
            dns_layer = pkt[DNS]
            
            if dns_layer.qr == 0:  # Query
                windows[dst_ip]["queries"] += 1
            elif dns_layer.qr == 1:  # Response
                windows[dst_ip]["responses"] += 1
                windows[dst_ip]["response_size"] += len(pkt)
                
        except queue.Empty:
            pass # No packets, check if window should close
            
        now = int(time.time())
        if now > current_window_start:
            # Process the completed 1-second window
            if windows:
                for dst_ip, stats in windows.items():
                    qps = stats["queries"]
                    rps = stats["responses"]
                    r_size = stats["response_size"]
                    
                    if qps == 0 and rps == 0:
                        continue
                        
                    avg_size = r_size / rps if rps > 0 else 0.0
                    ratio = rps / qps if qps > 0 else float(rps)
                    
                    # Hard rule fallback in case model is missing/crashing
                    label = "NORMAL"
                    conf = 1.0
                    
                    if ratio > 10.0 and avg_size > 500: # Typical amplification heuristic
                        label = "ATTACK"
                        conf = 0.99
                        
                    if model is not None:
                        features = pd.DataFrame([[qps, rps, ratio, avg_size]],
                            columns=["queries_per_sec", "responses_per_sec", "response_to_query_ratio", "avg_response_size"])
                        try:
                            conf = float(model.predict_proba(features)[0][1])
                            pred = int(model.predict(features)[0])
                            label = "ATTACK" if pred == 1 else "NORMAL"
                        except Exception as e:
                            pass # default to heuristic
                    
                    log_msg = f"Dst: {dst_ip} | QPS={qps}, RPS={rps}, Ratio={ratio:.1f}, AvgSize={avg_size:.1f}, Conf={conf:.2f}"
                    if label == "ATTACK":
                        logging.warning("[ATTACK] " + log_msg)
                    else:
                        logging.info("[NORMAL] " + log_msg)
                        
                    # Save to Postgres/SQLite
                    save_detection(dst_ip, qps, rps, ratio, avg_size, conf, label)
            
            # Reset window for the next second
            windows.clear()
            current_window_start = now


def start_live_monitor(iface: str):
    logging.info(f"Available Interfaces: {get_if_list()}")
    logging.info(f"Starting DNS Monitoring on interface: {iface}")
    
    # Start background worker
    worker_thread = threading.Thread(target=batch_processor, daemon=True)
    worker_thread.start()
    
    try:
        sniff(filter=PCAP_FILTER, prn=packet_handler, iface=iface, store=0)
    except KeyboardInterrupt:
        logging.info("Stopping monitor...")
    except Exception as e:
        logging.error(f"Sniffer error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Live DNS Amplification Detection")
    parser.add_argument("--interface", type=str, default=INTERFACE, help="Network interface to sniff on")
    args = parser.parse_args()
    
    os.makedirs("logs", exist_ok=True)
    start_live_monitor(args.interface)
