import pandas as pd
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay
import matplotlib.pyplot as plt
import os

df = pd.read_csv("data/extracted_features.csv")
X = df[["queries_per_sec", "responses_per_sec", "response_to_query_ratio", "avg_response_size"]]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = XGBClassifier(n_estimators=100, random_state=42, use_label_encoder=False, eval_metric="logloss")
model.fit(X_train, y_train)

y_pred = model.predict(X_test)

print("\nClassification Report (Test Set):")
print(classification_report(y_test, y_pred, target_names=["Normal", "Attack"]))

os.makedirs("models", exist_ok=True)
model.save_model("models/trained_xgboost_model.json")
print("Model saved to models/trained_xgboost_model.json")

report = classification_report(y_test, y_pred, output_dict=True)
df_report = pd.DataFrame(report).transpose()

os.makedirs("data", exist_ok=True)
df_report.to_csv("data/metrics_report.csv", index=True)
print("Classification report saved to data/metrics_report.csv")

cm = confusion_matrix(y_test, y_pred)
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Normal", "Attack"])
disp.plot(cmap="Blues")
plt.title("Confusion Matrix")
plt.savefig("data/confusion_matrix.png")
plt.close()
print("Confusion matrix image saved to data/confusion_matrix.png")

from xgboost import plot_importance
plot_importance(model, importance_type='weight', title='XGBoost Feature Importance')
plt.tight_layout()
plt.savefig("data/feature_importance.png")
plt.close()
print("Feature importance image saved to data/feature_importance.png")

y_full_pred = model.predict(X)
print("\nClassification Report (Entire Dataset):")
print(classification_report(y, y_full_pred, target_names=["Normal", "Attack"]))
