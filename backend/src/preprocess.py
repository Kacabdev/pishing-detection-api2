# preprocess.py
# Cleaning + scaling + stratified train/test split for the Phishing Websites dataset (UCI #327).
# Structured the same way as processingsample.py: inspect -> clean -> encode -> split -> scale -> save.
import json
import os

import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

CSV_PATH = "./dataset/phishing_websites.csv"
TRAIN_OUT_PATH = "./dataset/train.csv"
TEST_OUT_PATH = "./dataset/test.csv"
MODELS_DIR = "models"

TARGET_COL = "result"

# --------------------------------
# 1) Load + initial snapshot
# --------------------------------
df = pd.read_csv(CSV_PATH)

print("\n=== INITIAL HEAD ===")
print(df.head())

print("\n=== DATASET SHAPE ===")
print(df.shape)

print("\n=== DATASET INFO ===")
print(df.info())

print("\n=== MISSING VALUES ===")
print(df.isnull().sum().sum(), "missing values total")

print("\n=== DUPLICATE ROWS ===")
print(df.duplicated().sum())

# --------------------------------
# 2) Remove duplicates
# --------------------------------
before = df.shape[0]
df = df.drop_duplicates()
print(f"\nDropped duplicates: {before} -> {df.shape[0]} rows")

# --------------------------------
# 3) Confirm consistent numeric encoding
# --------------------------------
# Every feature in this dataset ships pre-encoded as {-1, 0, 1}; verify nothing slipped through
# before we trust it downstream instead of just describing it in a paper.
bad_cols = [c for c in df.columns if not set(df[c].unique()).issubset({-1, 0, 1})]
if bad_cols:
    raise ValueError(f"Unexpected values outside {{-1, 0, 1}} in columns: {bad_cols}")
print("\nAll columns confirmed within the expected {-1, 0, 1} encoding.")

# --------------------------------
# 4) Recode target: 1 = phishing, 0 = legitimate
# --------------------------------
# Dataset ships Result as -1 = phishing, 1 = legitimate. Flip it to the more conventional
# 1 = positive/phishing so precision/recall/F1 read the way the proposal describes them.
df[TARGET_COL] = df[TARGET_COL].map({-1: 1, 1: 0})

print("\n=== TARGET DISTRIBUTION (1 = phishing, 0 = legitimate) ===")
print(df[TARGET_COL].value_counts())
print(df[TARGET_COL].value_counts(normalize=True).round(3))

class_ratio = df[TARGET_COL].value_counts(normalize=True).min()
if class_ratio < 0.30:
    print("\nWarning: severely imbalanced classes - consider balancing techniques.")
else:
    print("\nClass balance OK for baseline Accuracy (both classes well represented).")

# --------------------------------
# 5) Train/test split (stratified) - the same split every model in train.py will use
# --------------------------------
X = df.drop(columns=[TARGET_COL])
y = df[TARGET_COL]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# --------------------------------
# 6) Scale numeric features (fit on train only, to avoid leakage)
# --------------------------------
feature_cols = X_train.columns.tolist()

scaler = StandardScaler()
X_train_scaled = pd.DataFrame(scaler.fit_transform(X_train), columns=feature_cols, index=X_train.index)
X_test_scaled = pd.DataFrame(scaler.transform(X_test), columns=feature_cols, index=X_test.index)

# --------------------------------
# 7) Save split datasets + scaler + feature order for training and serving
# --------------------------------
os.makedirs(MODELS_DIR, exist_ok=True)
joblib_path = os.path.join(MODELS_DIR, "scaler.pkl")

joblib.dump(scaler, joblib_path)
json.dump(feature_cols, open(os.path.join(MODELS_DIR, "feature_columns.json"), "w"), indent=2)

train_df = X_train_scaled.copy()
train_df[TARGET_COL] = y_train.values
test_df = X_test_scaled.copy()
test_df[TARGET_COL] = y_test.values

train_df.to_csv(TRAIN_OUT_PATH, index=False)
test_df.to_csv(TEST_OUT_PATH, index=False)

# --------------------------------
# 8) Final snapshot
# --------------------------------
print("\n=== FINAL TRAIN/TEST SPLIT ===")
print(f"Train: {train_df.shape[0]} rows, Test: {test_df.shape[0]} rows, Features: {len(feature_cols)}")

print(f"\nSaved train set -> {TRAIN_OUT_PATH}")
print(f"Saved test set -> {TEST_OUT_PATH}")
print(f"Saved scaler -> {joblib_path}")
print(f"Saved feature column order -> {MODELS_DIR}/feature_columns.json")
