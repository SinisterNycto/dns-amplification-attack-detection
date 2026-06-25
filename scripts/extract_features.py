from scapy.all import *
import pandas as pd
import numpy as np

def extract_dns_features(pcap_path, label=None):
    try:
        packets = rdpcap(pcap_path)
    except FileNotFoundError:
        print(f"File not found: {pcap_path}")
        return pd.DataFrame()

    data = []
    windows = {}
    
    for pkt in packets:
        if pkt.haslayer(DNS) and pkt.haslayer(IP):
            try:
                ip_layer = pkt[IP]
                dns_layer = pkt[DNS]
                
                # Use 1-second time windows
                ts = int(pkt.time)
                # Aggregate by Destination IP
                dst_ip = ip_layer.dst
                
                key = (ts, dst_ip)
                if key not in windows:
                    windows[key] = {
                        "queries_count": 0,
                        "responses_count": 0,
                        "total_response_size": 0,
                        "label": label
                    }
                
                if dns_layer.qr == 0:  # Query
                    windows[key]["queries_count"] += 1
                elif dns_layer.qr == 1:  # Response
                    windows[key]["responses_count"] += 1
                    windows[key]["total_response_size"] += len(pkt)
            except Exception as e:
                continue

    for (ts, dst_ip), stats in windows.items():
        q_count = stats["queries_count"]
        r_count = stats["responses_count"]
        r_size = stats["total_response_size"]
        
        avg_resp_size = r_size / r_count if r_count > 0 else 0
        ratio = r_count / q_count if q_count > 0 else float(r_count)
        
        row = {
            "timestamp": ts,
            "dst_ip": dst_ip,
            "queries_per_sec": q_count,
            "responses_per_sec": r_count,
            "response_to_query_ratio": ratio,
            "avg_response_size": avg_resp_size
        }
        if stats["label"] is not None:
            row["label"] = stats["label"]
            
        data.append(row)
        
    return pd.DataFrame(data)

if __name__ == "__main__":
    # core datasets
    df_normal = extract_dns_features("data/normal_traffic.pcap", label=0)
    df_clean = extract_dns_features("data/clean_normal_traffic.pcap", label=0)
    df_false_positive = extract_dns_features("data/false_positive_normal.pcap", label=0)
    df_attack = extract_dns_features("data/attack_traffic.pcap", label=1)
    df_ttl128 = extract_dns_features("data/ttl128_normal.pcap", label=0)
    df_spoofed_queries = extract_dns_features("data/spoofed_queries_only.pcap", label=1)
    df_spoofed_responses = extract_dns_features("data/spoofed_responses.pcap", label=1)
    df_diverse = extract_dns_features("data/diverse_normal_traffic.pcap", label=0)

    # combine
    df_final = pd.concat([
        df_normal,
        df_clean,
        df_attack,
        df_diverse,
        df_false_positive,
        df_ttl128,
        df_spoofed_queries,
        df_spoofed_responses
    ], ignore_index=True)

    if not df_final.empty:
        df_final.dropna(inplace=True)
        df_final.to_csv("data/extracted_features.csv", index=False)
        print("All features extracted and saved to data/extracted_features.csv")
    else:
        print("No data extracted. Ensure PCAP files exist in the data/ directory.")
