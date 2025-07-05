import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay
import joblib
import matplotlib.pyplot as plt
import os

# ==== Load Data ====
df = pd.read_csv("data/extracted_features.csv")
X = df[["packet_size", "query_type", "is_response", "ttl", "ancount", "likely_spoofed_response"]]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# ==== Train Model ====
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# ==== Predictions ====
y_pred = model.predict(X_test)

# ==== Print Classification Report ====
print("\n📊 Classification Report (Test Set):")
print(classification_report(y_test, y_pred, target_names=["Normal", "Attack"]))

# ==== Save Model ====
joblib.dump(model, "models/trained_model.pkl")
print("✅ Model saved to models/trained_model.pkl")

# ==== Export Classification Report to CSV ====
report = classification_report(y_test, y_pred, output_dict=True)
df_report = pd.DataFrame(report).transpose()

os.makedirs("data", exist_ok=True)
df_report.to_csv("data/metrics_report.csv", index=True)
print("✅ Classification report saved to data/metrics_report.csv")

# ==== Save Confusion Matrix as Image ====
cm = confusion_matrix(y_test, y_pred)
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Normal", "Attack"])
disp.plot(cmap="Blues")
plt.title("Confusion Matrix")
plt.savefig("data/confusion_matrix.png")
plt.close()
print("✅ Confusion matrix image saved to data/confusion_matrix.png")

# Optional: Also evaluate on full data
y_full_pred = model.predict(X)
print("\n📋 Classification Report (Entire Dataset):")
print(classification_report(y, y_full_pred, target_names=["Normal", "Attack"]))
