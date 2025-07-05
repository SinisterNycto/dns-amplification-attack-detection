# ML-Based Detection of DNS Amplification Attacks in Real-Time Traffic

This project implements an end-to-end system for detecting DNS Amplification Attacks using real-time network traffic monitoring combined with machine learning classification. It features a background packet sniffer that captures DNS traffic, extracts relevant features (like packet size, query type, TTL, etc.), and classifies the traffic as either normal or malicious using a trained Random Forest model.

A user-friendly Streamlit dashboard displays real-time detection logs, model metrics, and allows users to upload .pcap files for offline analysis. The system is lightweight, educational, and demonstrates how ML can be applied effectively in cybersecurity to detect amplification-based attacks in real-time.

---

## 📂 Project Structure

```
DNS-Amplification-Detection/
├── dashboard/
|    └── streamlit_app.py           # Streamlit Dashboard UI
|       
├── data/                         # Extracted features, confusion matrix, metrics
│   ├── extracted_features.csv
│   ├── metrics_report.csv
│   └── confusion_matrix.png
│
├── models/                      # Trained ML model
│   └── trained_model.pkl
│
├── logs/                        # Real-time detection logs
│   └── 
│
├── scripts/
│   ├── detect_live.py           # Background live traffic sniffer
│   ├── extract_features.py      # Extracts features from pcap files
│   └── train_model.py           # Trains the ML model  
|                  
└── README.md
```

---

## ⚙️ Installation

1. **Clone the repository**
```bash
git clone https://github.com/your-username/DNS-Amplification-Detection.git
cd DNS-Amplification-Detection
```

2. **Create virtual environment**
```bash
python -m venv venv
venv\Scripts\activate  # On Windows
source venv/bin/activate  # On Linux/Mac
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```
> If `requirements.txt` is not present, install manually:
```bash
pip install scapy pandas numpy scikit-learn matplotlib seaborn streamlit joblib
```

---

## 🔍 How to Use This Project

### ✅ Step 1: Run Live Detection Engine
Run the following script to start background DNS monitoring:
```bash
python scripts/detect_live.py
```

This will start capturing DNS traffic and write real-time detection logs to `logs/detection_log.txt`.

### ✅ Step 2: Launch Streamlit Dashboard
In a separate terminal, run:
```bash
streamlit run streamlit_app.py
```
Then open the browser tab that appears.

---

## 💡 How to Test Traffic

To simulate DNS queries:
```bash
nslookup google.com
```
Or run your own script like `spoof_batch.py` to simulate amplified queries.

---

## 🧠 How It Works
- Uses Scapy to sniff packets.
- Extracts features like packet size, TTL, query type, etc.
- Trained a Random Forest model to classify traffic.
- Logs all detections to a file.
- Streamlit visualizes logs and model metrics.


---


## 🛡️ Disclaimer
This project is for **educational and research purposes only**. Do not send spoofed packets to public DNS servers or external IPs.

---
> Note: All `.pcap` files used for training and testing were local traffic captures and are not included in the GitHub repository for privacy and size reasons. You can generate your own using tools like `Wireshark`, `Scapy`, or `spoof_batch.py`.
