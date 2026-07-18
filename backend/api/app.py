# app.py
# FastAPI service for the Phishing Website Detection project.
# Loads the best model saved by src/train.py (+ its scaler and feature order) and exposes
# a /predict endpoint, plus serves the static frontend that calls it.
import json
import os

import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "models")
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

model = joblib.load(os.path.join(MODELS_DIR, "best_model.pkl"))
scaler = joblib.load(os.path.join(MODELS_DIR, "scaler.pkl"))
feature_columns = json.load(open(os.path.join(MODELS_DIR, "feature_columns.json")))
model_info = json.load(open(os.path.join(MODELS_DIR, "model_info.json")))

app = FastAPI(title="Phishing Website Detection API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class PhishingFeatures(BaseModel):
    having_ip_address: int = Field(ge=-1, le=1)
    url_length: int = Field(ge=-1, le=1)
    shortining_service: int = Field(ge=-1, le=1)
    having_at_symbol: int = Field(ge=-1, le=1)
    double_slash_redirecting: int = Field(ge=-1, le=1)
    prefix_suffix: int = Field(ge=-1, le=1)
    having_sub_domain: int = Field(ge=-1, le=1)
    sslfinal_state: int = Field(ge=-1, le=1)
    domain_registration_length: int = Field(ge=-1, le=1)
    favicon: int = Field(ge=-1, le=1)
    port: int = Field(ge=-1, le=1)
    https_token: int = Field(ge=-1, le=1)
    request_url: int = Field(ge=-1, le=1)
    url_of_anchor: int = Field(ge=-1, le=1)
    links_in_tags: int = Field(ge=-1, le=1)
    sfh: int = Field(ge=-1, le=1)
    submitting_to_email: int = Field(ge=-1, le=1)
    abnormal_url: int = Field(ge=-1, le=1)
    redirect: int = Field(ge=-1, le=1)
    on_mouseover: int = Field(ge=-1, le=1)
    rightclick: int = Field(ge=-1, le=1)
    popupwindow: int = Field(ge=-1, le=1)
    iframe: int = Field(ge=-1, le=1)
    age_of_domain: int = Field(ge=-1, le=1)
    dnsrecord: int = Field(ge=-1, le=1)
    web_traffic: int = Field(ge=-1, le=1)
    page_rank: int = Field(ge=-1, le=1)
    google_index: int = Field(ge=-1, le=1)
    links_pointing_to_page: int = Field(ge=-1, le=1)
    statistical_report: int = Field(ge=-1, le=1)


class PredictionResponse(BaseModel):
    prediction: str
    phishing_probability: float
    legitimate_probability: float
    model: str


@app.get("/health")
def health():
    return {"status": "ok", "model": model_info["algorithm"], "metrics": model_info["metrics"]}


@app.post("/predict", response_model=PredictionResponse)
def predict(features: PhishingFeatures):
    row = features.model_dump()
    try:
        X = pd.DataFrame([[row[col] for col in feature_columns]], columns=feature_columns)
    except KeyError as exc:
        raise HTTPException(status_code=400, detail=f"Missing feature: {exc}")

    X_scaled = pd.DataFrame(scaler.transform(X), columns=feature_columns)

    phishing_probability = float(model.predict_proba(X_scaled)[0, 1])
    prediction = "phishing" if phishing_probability >= 0.5 else "legitimate"

    return PredictionResponse(
        prediction=prediction,
        phishing_probability=round(phishing_probability, 4),
        legitimate_probability=round(1 - phishing_probability, 4),
        model=model_info["algorithm"],
    )


if os.path.isdir(FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
