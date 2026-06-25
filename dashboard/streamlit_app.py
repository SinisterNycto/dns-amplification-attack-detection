import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import os
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import DATABASE_URL
from src.database import DetectionLog

st.set_page_config(page_title="DNS Amplification Attack Detection", layout="wide")
st.title("DNS Amplification Attack Detection Dashboard")

# Initialize DB connection
try:
    engine = create_engine(DATABASE_URL)
    
    # Ensure the table is created before querying (fixes Streamlit Cloud OperationalError)
    from src.database import Base
    Base.metadata.create_all(engine)
    
    Session = sessionmaker(bind=engine)
    session = Session()
except Exception as e:
    st.error(f"Failed to connect to database: {e}")
    session = None

menu = ["Live Monitor", "Model Metrics", "PCAP Analyzer"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Live Monitor":
    st.subheader("Real-time Traffic Monitoring")
    st.info("Reading live logs from Database (PostgreSQL / SQLite).")

    if session:
        # Fetch the last 50 logs
        recent_logs = session.query(DetectionLog).order_by(DetectionLog.timestamp.desc()).limit(50).all()
        
        if recent_logs:
            # Convert to DataFrame for display
            df = pd.DataFrame([{
                "Time": log.timestamp.strftime("%Y-%m-%d %H:%M:%S") if log.timestamp else None,
                "Target IP": log.dst_ip,
                "QPS": log.queries_per_sec,
                "RPS": log.responses_per_sec,
                "Ratio": round(log.response_to_query_ratio, 2),
                "Avg Size": round(log.avg_response_size, 2),
                "Confidence": round(log.confidence, 2),
                "Status": log.label
            } for log in recent_logs])
            
            # Highlight attacks in red
            def color_attack(val):
                color = 'red' if val == 'ATTACK' else 'green'
                return f'color: {color}'
            
            styled_df = df.style.map(color_attack, subset=['Status'])
            st.dataframe(styled_df, use_container_width=True)
            
            # Simple chart of RPS over the last 50 entries
            st.subheader("Responses Per Second (RPS) Trend")
            df_chart = df[["Time", "RPS"]].set_index("Time").sort_index()
            st.line_chart(df_chart)
        else:
            st.warning("No logs found in the database. Run `python scripts/detect_live.py`.")
            
        import time
        time.sleep(2)
        st.rerun()

elif choice == "Model Metrics":
    st.subheader("Traffic Summary (Live)")
    
    if session:
        total_packets = session.query(DetectionLog).count()
        attack_count = session.query(DetectionLog).filter(DetectionLog.label == "ATTACK").count()
        normal_count = session.query(DetectionLog).filter(DetectionLog.label == "NORMAL").count()
        
        col1, col2 = st.columns(2)
        col1.metric("Total Windows Analyzed", str(total_packets))
        col2.metric("Detected Attacks", str(attack_count))

        if total_packets > 0:
            labels = ["Normal", "Attack"]
            sizes = [normal_count, attack_count]
            fig, ax = plt.subplots()
            ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, colors=['#4CAF50', '#F44336'])
            ax.axis('equal')
            st.pyplot(fig)
        else:
            st.info("No traffic detected yet.")
            
    st.markdown("---")
    st.subheader("Model Performance Report")
    try:
        report_df = pd.read_csv("data/metrics_report.csv", index_col=0)
        
        col1, col2, col3, col4 = st.columns(4)
        # Handle accuracy being in the index differently depending on sklearn version
        acc = report_df.loc['accuracy', 'f1-score'] if 'accuracy' in report_df.index else 1.0
        col1.metric("Overall Accuracy", f"{acc * 100:.2f}%")
        
        if 'Attack' in report_df.index:
            col2.metric("Attack Precision", f"{report_df.loc['Attack', 'precision'] * 100:.2f}%")
            col3.metric("Attack Recall", f"{report_df.loc['Attack', 'recall'] * 100:.2f}%")
            col4.metric("F1-Score", f"{report_df.loc['Attack', 'f1-score'] * 100:.2f}%")
            
    except Exception as e:
        st.warning("Could not load metrics_report.csv nicely. Train the model first.")

    st.markdown("---")
    st.subheader("Model Insights")
    
    col_cm, col_fi = st.columns(2)
    
    with col_cm:
        st.markdown("**Confusion Matrix**")
        cm_path = "data/confusion_matrix.png"
        if os.path.exists(cm_path):
            st.image(cm_path, use_container_width=True)
            
    with col_fi:
        st.markdown("**XGBoost Feature Importance**")
        fi_path = "data/feature_importance.png"
        if os.path.exists(fi_path):
            st.image(fi_path, use_container_width=True)

elif choice == "PCAP Analyzer":
    st.subheader("Upload & Analyze PCAP")
    st.info("Upload a `.pcap` file containing DNS traffic to test the Machine Learning detection engine.")
    
    col1, col2 = st.columns([3, 1])
    with col1:
        uploaded_file = st.file_uploader("Upload a .pcap file", type=["pcap", "pcapng"])
    with col2:
        st.write("")
        st.write("")
        if os.path.exists("data/sample_attack.pcap"):
            with open("data/sample_attack.pcap", "rb") as f:
                st.download_button("Download Sample PCAP", data=f, file_name="sample_attack.pcap", mime="application/vnd.tcpdump.pcap")

    if uploaded_file is not None:
        file_path = os.path.join("data", "uploaded_traffic.pcap")
        with open(file_path, "wb") as f:
            f.write(uploaded_file.read())
        
        st.success("PCAP uploaded successfully! Analyzing...")
        
        with st.spinner("Extracting volumetric features..."):
            from scripts.extract_features import extract_dns_features
            df_features = extract_dns_features(file_path, label=None)
            
        if df_features.empty:
            st.warning("No DNS traffic found in the uploaded PCAP.")
        else:
            with st.spinner("Running XGBoost Inference..."):
                from xgboost import XGBClassifier
                
                try:
                    model = XGBClassifier()
                    model.load_model("models/trained_xgboost_model.json")
                    
                    X = df_features[["queries_per_sec", "responses_per_sec", "response_to_query_ratio", "avg_response_size"]]
                    predictions = model.predict(X)
                    probabilities = model.predict_proba(X)[:, 1]
                    
                    df_features["Prediction"] = ["ATTACK" if p == 1 else "NORMAL" for p in predictions]
                    df_features["Confidence"] = [round(prob, 2) for prob in probabilities]
                    
                    def color_attack(val):
                        color = 'red' if val == 'ATTACK' else 'green'
                        return f'color: {color}'
                    
                    st.subheader("Detection Results")
                    styled_df = df_features.style.map(color_attack, subset=['Prediction'])
                    st.dataframe(styled_df, use_container_width=True)
                    
                    attacks_found = sum(predictions)
                    if attacks_found > 0:
                        st.error(f"🚨 Detected {attacks_found} attack windows in this PCAP!")
                    else:
                        st.success("✅ No attacks detected. Traffic looks normal.")
                        
                except Exception as e:
                    st.error(f"Error loading model or running inference: {e}")

st.markdown("---")
st.caption("Developed for ML-Based Detection of DNS Amplification Attacks")
