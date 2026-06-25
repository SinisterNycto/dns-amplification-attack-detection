# DNS Amplification Attack Detector

A two-part system for detecting DNS Amplification DDoS attacks using machine learning. 

This project consists of:
1. **An Edge Sniffer (`detect_live.py`)**: A lightweight Python script designed to run locally on a server or router. It sniffs raw network traffic in real-time, extracts volumetric time-window features, and logs suspicious activity to a local SQLite database.
2. **A Web Dashboard**: A Streamlit web application that visualizes the real-time database logs. It also includes a public-facing "PCAP Analyzer" tab that allows security researchers to upload `.pcap` files and run them through the XGBoost model directly in the browser.

## Tech Stack
- **Machine Learning**: XGBoost, Scikit-learn, Pandas
- **Networking**: Scapy (for PCAP parsing and live packet sniffing)
- **Frontend**: Streamlit
- **Database**: SQLAlchemy (SQLite by default, compatible with PostgreSQL)

## Features
- **Live Traffic Monitoring**: Sniffs packets on your network card and calculates queries/sec, responses/sec, and response size averages in 1-second rolling windows.
- **XGBoost Inference**: Uses a pre-trained XGBClassifier with 100% test accuracy on synthetic attack data to evaluate traffic windows.
- **PCAP Analysis**: A web-based analyzer where you can upload `.pcap` files and instantly see which timestamps contain DDoS traffic. 
- **Explainable AI**: Generates Feature Importance plots to demonstrate exactly which volumetric metrics trigger the XGBoost detection.

---

## Installation & Setup

1. **Clone the repository**
```bash
git clone https://github.com/SinisterNycto/dns-amplification-attack-detection.git
cd dns-amplification-attack-detection
```

2. **Set up the virtual environment**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Running the Project

### 1. The Web Dashboard (Cloud-Ready)
To start the Streamlit interface (which includes the Live Database Viewer, Model Metrics, and the PCAP Analyzer):
```bash
source venv/bin/activate
streamlit run dashboard/streamlit_app.py
```
*Note: The PCAP Analyzer is fully functional when deployed to cloud hosts like Streamlit Community Cloud.*

### 2. The Live Network Sniffer (Local Only)
To run the live detection engine on your physical machine, you need `sudo` privileges to sniff raw packets off your network card:
```bash
source venv/bin/activate
sudo venv/bin/python scripts/detect_live.py --interface en0
```
*(If you are on Windows or Linux, change `en0` to your active network interface like `Wi-Fi` or `eth0`).*

### 3. Simulating an Attack
While the live sniffer is running, you can run the spoofing script to simulate a massive burst of DNS responses hitting your machine:
```bash
source venv/bin/activate
sudo venv/bin/python scripts/spoof_batch.py
```
Check the Streamlit dashboard—it will instantly flag the attack window in red!

---

## Project Structure

- `dashboard/`: Contains the Streamlit app.
- `scripts/`: Core logic including the live sniffer, ML training script, Scapy traffic simulators, and PCAP generators.
- `data/`: Sample `.pcap` files and exported model metrics (Confusion Matrix, Feature Importance).
- `models/`: The saved XGBoost JSON model.

## Disclaimer
This project is strictly for educational and cybersecurity research purposes. Do not use the spoofing scripts against infrastructure you do not own.
