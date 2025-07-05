from scapy.all import *
import pandas as pd

def extract_dns_features(pcap_path, label):
    packets = rdpcap(pcap_path)
    data = []

    for pkt in packets:
        if pkt.haslayer(DNS) and pkt.haslayer(IP):
            try:
                ip_layer = pkt[IP]
                dns_layer = pkt[DNS]

                row = {
                    "src_ip": ip_layer.src,
                    "dst_ip": ip_layer.dst,
                    "packet_size": len(pkt),
                    "query_type": dns_layer.qd.qtype if hasattr(dns_layer, "qd") and dns_layer.qd else 0,
                    "is_response": dns_layer.qr,
                    "ttl": ip_layer.ttl,
                    "ancount": dns_layer.ancount,
                    "likely_spoofed_response": 1 if dns_layer.qr == 1 and ip_layer.ttl <= 64 and dns_layer.ancount == 0 and len(pkt) <= 80 else 0,
                    "label": label
                }
                data.append(row)
            except:
                continue

    return pd.DataFrame(data)

# ✅ Step 1: Core datasets
df_normal = extract_dns_features("data/normal_traffic.pcap", label=0)
df_clean = extract_dns_features("data/clean_normal_traffic.pcap", label=0)
df_false_positive = extract_dns_features("data/false_positive_normal.pcap", label=0)
df_attack = extract_dns_features("data/attack_traffic.pcap", label=1)
df_ttl128 = extract_dns_features("data/ttl128_normal.pcap", label=0)
df_spoofed_queries = extract_dns_features("data/spoofed_queries_only.pcap", label=1)
df_spoofed_responses = extract_dns_features("data/spoofed_responses.pcap", label=1)

# ✅ Step 3: Add diverse DNS queries (real-world normal)
df_diverse = extract_dns_features("data/diverse_normal_traffic.pcap", label=0)

# ✅ Step 2 (Optional): Add false positives from live detection (label as normal)
try:
    df_false_positive = extract_dns_features("data/false_positive_normal.pcap", label=0)
except FileNotFoundError:
    df_false_positive = pd.DataFrame()  # handle if not yet created

# ✅ Combine all
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

# ✅ Clean and save
df_final.dropna(inplace=True)
df_final.to_csv("data/extracted_features.csv", index=False)
print("✅ All features extracted and saved to data/extracted_features.csv")
