import pytest
import requests
import subprocess
import time
import sys

BASE_URL = "http://localhost:8000"

def test_health():
    response = requests.get(f"{BASE_URL}/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "threshold" in data

def test_predict_normal():
    sample = {
        "event_id": "test_normal_001",
        "client_useragent": "Mozilla/5.0 Chrome",
        "matched_variable_value": "page=home",
        "request_size": 500,
        "response_code": 200
    }
    response = requests.post(f"{BASE_URL}/predict", json=sample)
    assert response.status_code == 200
    data = response.json()
    assert data["event_id"] == "test_normal_001"
    assert data["label_pred"] == 0  # не атака

def test_predict_sqli():
    sample = {
        "event_id": "test_sqli_001",
        "client_useragent": "sqlmap/1.0",
        "matched_variable_value": "1' UNION SELECT * FROM users--",
        "request_size": 300,
        "response_code": 404
    }
    response = requests.post(f"{BASE_URL}/predict", json=sample)
    assert response.status_code == 200
    data = response.json()
    assert data["label_pred"] == 1  # атака
    assert data["is_attack"] == True

def test_predict_xss():
    sample = {
        "event_id": "test_xss_001",
        "matched_variable_value": "<script>alert(1)</script>"
    }
    response = requests.post(f"{BASE_URL}/predict", json=sample)
    assert response.status_code == 200
    data = response.json()
    assert data["label_pred"] == 1

def test_predict_batch():
    """Проверка пакетной обработки"""
    batch = {
        "samples": [
            {
                "event_id": "batch_1",
                "matched_variable_value": "normal_page"
            },
            {
                "event_id": "batch_2",
                "matched_variable_value": "1' OR '1'='1"
            },
            {
                "event_id": "batch_3",
                "matched_variable_value": "../../etc/passwd"
            }
        ]
    }
    response = requests.post(f"{BASE_URL}/predict_batch", json=batch)
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 3
    assert data[0]["label_pred"] == 0
    assert data[1]["label_pred"] == 1  
    assert data[2]["label_pred"] == 1  

if __name__ == "__main__":
    pytest.main([__file__, "-v"])