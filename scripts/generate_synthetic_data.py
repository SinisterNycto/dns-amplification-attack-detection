import pandas as pd
import numpy as np
import os

# Set seed for reproducibility
np.random.seed(42)

# Generate Normal Traffic (10,000 samples)
# Normal traffic has low QPS, low RPS, ratio ~ 1.0, small response sizes
normal_qps = np.random.randint(1, 30, 10000)
normal_rps = normal_qps + np.random.randint(-2, 3, 10000)
normal_rps = np.where(normal_rps < 0, 0, normal_rps) # no negative
normal_ratio = np.where(normal_qps > 0, normal_rps / normal_qps, normal_rps)
normal_size = np.random.normal(150, 40, 10000) # Avg response size ~ 150 bytes
normal_label = np.zeros(10000)

# Generate Attack Traffic (Amplification) (5,000 samples)
# Attack traffic has almost 0 QPS, huge RPS, massive ratio, large response sizes
attack_qps = np.random.randint(0, 3, 5000)
attack_rps = np.random.randint(200, 5000, 5000)
attack_ratio = np.where(attack_qps > 0, attack_rps / attack_qps, attack_rps)
attack_size = np.random.normal(3000, 500, 5000) # Amplified responses ~ 3000+ bytes
attack_label = np.ones(5000)

# Combine into a DataFrame
df_normal = pd.DataFrame({
    "queries_per_sec": normal_qps,
    "responses_per_sec": normal_rps,
    "response_to_query_ratio": normal_ratio,
    "avg_response_size": normal_size,
    "label": normal_label
})

df_attack = pd.DataFrame({
    "queries_per_sec": attack_qps,
    "responses_per_sec": attack_rps,
    "response_to_query_ratio": attack_ratio,
    "avg_response_size": attack_size,
    "label": attack_label
})

df = pd.concat([df_normal, df_attack]).sample(frac=1).reset_index(drop=True)

# Save to data/extracted_features.csv
os.makedirs("data", exist_ok=True)
df.to_csv("data/extracted_features.csv", index=False)
print("Synthetic dataset successfully created at data/extracted_features.csv!")
