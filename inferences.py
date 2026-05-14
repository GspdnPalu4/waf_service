from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional
import pandas as pd
import numpy as np
import joblib
import re
import os
from pathlib import Path
import uvicorn

app = FastAPI(
    title="WAF ML Service",
    description="Сервис классификации вредоносных запросов",
    version="1.0.0"
)

# Загрузка модели при старте
MODEL_PATH = Path("models/waf_model.pkl")
THRESHOLD_PATH = Path("models/threshold.pkl")

model = joblib.load(MODEL_PATH)
threshold = joblib.load(THRESHOLD_PATH)
print(f"Модель загружена из {MODEL_PATH}")
print(f"Порог классификации: {threshold:.4f}")

class RequestSample(BaseModel):
    event_id: str = Field(..., description="Уникальный ID события")
    client_ip: Optional[str] = Field(None, description="IP-адрес клиента")
    client_useragent: Optional[str] = Field(None, description="User-Agent")
    request_size: Optional[float] = Field(None, description="Размер запроса")
    response_code: Optional[float] = Field(None, description="HTTP код ответа")
    matched_variable_src: Optional[str] = Field(None, description="Источник срабатывания")
    matched_variable_name: Optional[str] = Field(None, description="Имя переменной")
    matched_variable_value: Optional[str] = Field(None, description="Значение переменной")

class PredictionResponse(BaseModel):
    event_id: str
    label_pred: int = Field(description="0 - норма, 1 - атака")
    probability: float = Field(description="Вероятность атаки")
    is_attack: bool = Field(description="Флаг атаки")

class BatchRequest(BaseModel):
    samples: List[RequestSample]

class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    threshold: float
    version: str

def _entropy(s: str) -> float:
    if len(s) <= 1:
        return 0.0
    prob = [s.count(c) / len(s) for c in set(s)]
    return float(-sum(p * np.log2(p) for p in prob))

def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    
    # Текстовые колонки для векторизации
    df['payload_text'] = (
        df['MATCHED_VARIABLE_VALUE'].fillna('') + ' ' +
        df['MATCHED_VARIABLE_NAME'].fillna('') + ' ' +
        df['MATCHED_VARIABLE_SRC'].fillna('')
    )
    
    # Числовые признаки
    df['req_size_log'] = np.log1p(df['REQUEST_SIZE'].fillna(0).astype(float))
    df['is_error_code'] = df['RESPONSE_CODE'].isin([403, 404, 500, 502, 503]).astype(int)
    df['ua_length'] = df['CLIENT_USERAGENT'].fillna('').str.len()
    
    # Признаки из User-Agent
    ua = df['CLIENT_USERAGENT'].fillna('').str.lower()
    df['is_bot'] = ua.str.contains('bot|crawler|spider|scanner', regex=True).astype(int)
    df['is_tool'] = ua.str.contains('curl|wget|python|sqlmap|nikto|dirbuster|openvas', regex=True).astype(int)
    
    # Признаки из MATCHED_VARIABLE_VALUE
    val = df['MATCHED_VARIABLE_VALUE'].fillna('').str.lower()
    
    df['has_sql_keywords'] = val.str.contains(
        r'\b(select|union|insert|delete|update|drop|exec|declare|sleep|benchmark|waitfor)\b', 
        regex=True, case=False
    ).astype(int)
    
    df['has_sql_comments'] = val.str.contains(r'/\*|\*/|--\s|#', regex=True).astype(int)
    
    df['has_xss'] = val.str.contains(
        r'<script|<img|<svg|onerror|onload|javascript:|alert\(', 
        regex=True, case=False
    ).astype(int)
    
    df['has_path_traversal'] = val.str.contains(
        r'\.\./|\.\.\\|%2e%2e|/etc/passwd|win\.ini|boot\.ini', 
        regex=True, case=False
    ).astype(int)
    
    df['has_cmd_injection'] = val.str.contains(
        r'\$\{|`|\bls\b|\bcat\b|\bpwd\b|\bid\b|;|\|', 
        regex=True, case=False
    ).astype(int)
    
    df['has_url_encoding'] = val.str.contains(r'%[0-9a-fA-F]{2}', regex=True).astype(int)
    df['has_hex_encoding'] = val.str.contains(r'0x[0-9a-fA-F]+', regex=True).astype(int)
    
    df['payload_entropy'] = val.apply(lambda x: _entropy(str(x)) if len(str(x)) > 0 else 0)
    
    df['payload_len'] = val.str.len()
    df['special_chars_ratio'] = val.str.replace(r'[a-zA-Z0-9\s]', '', regex=True).str.len() / \
                                df['payload_len'].clip(lower=1)
    
    df['matched_src_is_headers'] = df['MATCHED_VARIABLE_SRC'].str.contains('HEADERS', na=False).astype(int)
    df['matched_src_is_cookies'] = df['MATCHED_VARIABLE_SRC'].str.contains('COOKIES', na=False).astype(int)
    df['matched_src_is_uri'] = df['MATCHED_VARIABLE_SRC'].str.contains('URI', na=False).astype(int)
    
    return df

def preprocess_for_prediction(samples: List[RequestSample]) -> pd.DataFrame:
    records = [s.dict() for s in samples]
    df = pd.DataFrame(records)
    
    df = df.rename(columns={
        'client_ip': 'CLIENT_IP',
        'client_useragent': 'CLIENT_USERAGENT',
        'request_size': 'REQUEST_SIZE',
        'response_code': 'RESPONSE_CODE',
        'matched_variable_src': 'MATCHED_VARIABLE_SRC',
        'matched_variable_name': 'MATCHED_VARIABLE_NAME',
        'matched_variable_value': 'MATCHED_VARIABLE_VALUE'
    })

    df = extract_features(df)
    
    feature_cols = [
        'payload_text',  
        'req_size_log', 'ua_length', 'payload_len', 'payload_entropy', 'special_chars_ratio', 
        'is_error_code', 'is_bot', 'is_tool',
        'has_sql_keywords', 'has_sql_comments', 'has_xss',
        'has_path_traversal', 'has_cmd_injection',
        'has_url_encoding', 'has_hex_encoding',
        'matched_src_is_headers', 'matched_src_is_cookies', 'matched_src_is_uri' 
    ]
    
    df = df[feature_cols].fillna('')
    return df

@app.get("/health", response_model=HealthResponse)
async def health_check():
    return HealthResponse(
        status="healthy",
        model_loaded=True,
        threshold=float(threshold),
        version="1.0.0"
    )

@app.post("/predict", response_model=PredictionResponse)
async def predict_single(sample: RequestSample):
    try:
        df = preprocess_for_prediction([sample])
        proba = model.predict_proba(df)[0, 1]
        pred = 1 if proba >= threshold else 0
        
        return PredictionResponse(
            event_id=sample.event_id,
            label_pred=pred,
            probability=float(proba),
            is_attack=bool(pred)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка предсказания: {str(e)}")

@app.post("/predict_batch", response_model=List[PredictionResponse])
async def predict_batch(request: BatchRequest):
    try:
        if not request.samples:
            raise HTTPException(status_code=400, detail="Пустой список сэмплов")
        
        df = preprocess_for_prediction(request.samples)
        probas = model.predict_proba(df)[:, 1]
        preds = (probas >= threshold).astype(int)
        
        results = []
        for i, sample in enumerate(request.samples):
            results.append(PredictionResponse(
                event_id=sample.event_id,
                label_pred=int(preds[i]),
                probability=float(probas[i]),
                is_attack=bool(preds[i])
            ))
        
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка пакетного предсказания: {str(e)}")

@app.get("/")
async def root():
    return {"message": "WAF ML Service API", "docs": "/docs"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)