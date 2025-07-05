import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

# Page Configuration
st.set_page_config(page_title="DNS Amplification Attack Detection", layout="wide")
st.title("🔍 DNS Amplification Attack Detection Dashboard")

# Sidebar Navigation
menu = ["Live Monitor", "Model Metrics", "Logs"]
choice = st.sidebar.selectbox("Navigation", menu)

# --- Live Monitor ---
if choice == "Live Monitor":
    st.subheader("🛡️ Real-time Traffic Monitoring")
    st.info("This section shows real-time detection results from your running system.")

    log_path = "logs/detection_log.txt"
    if os.path.exists(log_path):
        with open(log_path, "r", encoding="utf-8") as f:
            logs = f.read()
        st.code(logs, language='text')
    else:
        st.warning("No detection log found. Make sure detect_live.py is running and logging to logs/detection_log.txt")

# --- Model Metrics ---
elif choice == "Model Metrics":
    st.subheader("📊 Model Performance Report")

    try:
        report_df = pd.read_csv("data/metrics_report.csv")
        st.dataframe(report_df)
    except FileNotFoundError:
        st.warning("metrics_report.csv not found. Make sure to export classification_report to CSV.")

    st.subheader("📊 Confusion Matrix")
    cm_path = "data/confusion_matrix.png"
    if os.path.exists(cm_path):
        st.image(cm_path, caption="Confusion Matrix")
    else:
        st.warning("confusion_matrix.png not found. Please generate and save it from your training script.")

    st.subheader("📊 Traffic Summary (Live)")
    log_path = "logs/detection_log.txt"
    normal_count = 0
    attack_count = 0

    if os.path.exists(log_path):
        with open(log_path, "r", encoding="utf-8") as f:
            for line in f:
                if "[ATTACK]" in line:
                    attack_count += 1
                elif "[NORMAL]" in line:
                    normal_count += 1
    else:
        st.warning("detection_log.txt not found. Run detect_live.py first.")

    total_packets = normal_count + attack_count

    col1, col2 = st.columns(2)
    col1.metric("Total Packets Analyzed", str(total_packets))
    col2.metric("Detected Attacks", str(attack_count))

    # Pie chart (live values)
    if total_packets > 0:
        labels = ["Normal", "Attack"]
        sizes = [normal_count, attack_count]
        fig, ax = plt.subplots()
        ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
        ax.axis('equal')
        st.pyplot(fig)
    else:
        st.info("No traffic detected yet.")

# --- Upload PCAP Logs ---
elif choice == "Logs":
    st.subheader("📂 Upload & Analyze PCAP")
    uploaded_file = st.file_uploader("Upload a .pcap file", type=["pcap"])

    if uploaded_file is not None:
        file_path = os.path.join("data", "uploaded_traffic.pcap")
        with open(file_path, "wb") as f:
            f.write(uploaded_file.read())
        st.success("PCAP uploaded and saved!")
        st.info("You can now run your feature extraction + detection script on it manually.")

st.markdown("---")
st.caption("Developed for ML-Based Detection of DNS Amplification Attacks")
