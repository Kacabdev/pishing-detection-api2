# train.py
# Trains all required algorithms on the exact same preprocessed split, prints a comparison
# table, and saves only the best model (by F1, tie-broken by Recall) for the API to serve.
import json
import os

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from xgboost import XGBClassifier

TRAIN_PATH = "./dataset/train.csv"
TEST_PATH = "./dataset/test.csv"
MODELS_DIR = "models"
TARGET_COL = "result"

train_df = pd.read_csv(TRAIN_PATH)
test_df = pd.read_csv(TEST_PATH)

X_train = train_df.drop(columns=[TARGET_COL])
y_train = train_df[TARGET_COL]
X_test = test_df.drop(columns=[TARGET_COL])
y_test = test_df[TARGET_COL]

print(f"Train rows: {X_train.shape[0]}, Test rows: {X_test.shape[0]}, Features: {X_train.shape[1]}")

# --------------------------------
# 1) Define every algorithm to compare (same train/test split for all of them)
# --------------------------------
models = {
    "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42),
    "Random Forest": RandomForestClassifier(n_estimators=300, random_state=42),
    "XGBoost": XGBClassifier(n_estimators=300, eval_metric="logloss", random_state=42),
}

# --------------------------------
# 2) Train + evaluate each model on the identical held-out test set
# --------------------------------
results = []
fitted_models = {}

for name, model in models.items():
    model.fit(X_train, y_train)
    fitted_models[name] = model

    y_pred = model.predict(X_test)

    metrics = {
        "Algorithm": name,
        "Accuracy": accuracy_score(y_test, y_pred),
        "Precision": precision_score(y_test, y_pred),
        "Recall": recall_score(y_test, y_pred),
        "F1": f1_score(y_test, y_pred),
    }
    results.append(metrics)

    print(f"\n=== {name} ===")
    print(f"Accuracy:  {metrics['Accuracy']:.4f}")
    print(f"Precision: {metrics['Precision']:.4f}")
    print(f"Recall:    {metrics['Recall']:.4f}")
    print(f"F1-Score:  {metrics['F1']:.4f}")
    print("Confusion Matrix (rows=actual, cols=predicted, [legit, phishing]):")
    print(confusion_matrix(y_test, y_pred))

# --------------------------------
# 3) Comparison table
# --------------------------------
comparison_df = pd.DataFrame(results).sort_values("F1", ascending=False).reset_index(drop=True)
print("\n=== MODEL COMPARISON (sorted by F1) ===")
print(comparison_df.to_string(index=False))

os.makedirs(MODELS_DIR, exist_ok=True)
comparison_df.to_csv(os.path.join(MODELS_DIR, "comparison_table.csv"), index=False)

# --------------------------------
# 4) Select the best model: highest F1, tie-broken by Recall
# --------------------------------
best_row = comparison_df.sort_values(["F1", "Recall"], ascending=False).iloc[0]
best_name = best_row["Algorithm"]
best_model = fitted_models[best_name]

print(f"\nBest model: {best_name} (F1={best_row['F1']:.4f}, Recall={best_row['Recall']:.4f})")

joblib.dump(best_model, os.path.join(MODELS_DIR, "best_model.pkl"))
json.dump(
    {"algorithm": best_name, "metrics": best_row.drop("Algorithm").to_dict()},
    open(os.path.join(MODELS_DIR, "model_info.json"), "w"),
    indent=2,
)
print(f"Saved best model -> {MODELS_DIR}/best_model.pkl")

# --------------------------------
# 5) Sanity checks: sample predictions from the best model
# --------------------------------
print("\n=== SANITY CHECKS (best model, 3 sample test rows) ===")
sample = X_test.sample(n=3, random_state=7)
sample_true = y_test.loc[sample.index]
sample_pred = best_model.predict(sample)
sample_proba = best_model.predict_proba(sample)[:, 1]

for i, idx in enumerate(sample.index):
    label = {1: "phishing", 0: "legitimate"}
    print(f"\nRow {idx}:")
    print(sample.loc[idx].to_dict())
    print(
        f"True label: {label[sample_true.loc[idx]]} | "
        f"Predicted: {label[sample_pred[i]]} | "
        f"Phishing probability: {sample_proba[i]:.4f}"
    )
