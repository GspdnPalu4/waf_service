import requests
import pandas as pd
from typing import List, Dict
import sys

class WAFClient:
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.predict_url = f"{base_url}/predict"
        self.batch_url = f"{base_url}/predict_batch"
        self.health_url = f"{base_url}/health"
    
    def check_health(self) -> Dict:
        response = requests.get(self.health_url)
        return response.json()
    
    def predict_single(self, event_id: str, matched_variable_value: str = None, 
                       client_useragent: str = None, **kwargs) -> Dict:
        sample = {
            "event_id": event_id,
            "matched_variable_value": matched_variable_value,
            "client_useragent": client_useragent,
            **kwargs
        }
        response = requests.post(self.predict_url, json=sample)
        response.raise_for_status()
        return response.json()
    
    def predict_batch(self, samples: List[Dict]) -> List[Dict]:
        response = requests.post(self.batch_url, json={"samples": samples})
        response.raise_for_status()
        return response.json()
    
    def test_with_csv(self, csv_path: str, limit: int = None) -> pd.DataFrame:
        """Отправить данные из CSV и получить результаты"""
        df = pd.read_csv(csv_path)
        
        if limit:
            df = df.head(limit)
        
        samples = []
        for idx, row in df.iterrows():
            try:
                request_size = None
                raw_size = row.get('REQUEST_SIZE', 0)
                if pd.notna(raw_size):
                    try:
                        request_size = float(raw_size)
                    except (ValueError, TypeError):
                        request_size = 0
                
                response_code = None
                raw_code = row.get('RESPONSE_CODE', 0)
                if pd.notna(raw_code):
                    try:
                        response_code = int(float(raw_code))
                    except (ValueError, TypeError):
                        response_code = 200
                
                sample = {
                    "event_id": str(row.get('EVENT_ID', f'row_{idx}')),
                    "client_ip": str(row.get('CLIENT_IP', '')) if pd.notna(row.get('CLIENT_IP')) else None,
                    "client_useragent": str(row.get('CLIENT_USERAGENT', '')) if pd.notna(row.get('CLIENT_USERAGENT')) else None,
                    "request_size": request_size,
                    "response_code": response_code,
                    "matched_variable_src": str(row.get('MATCHED_VARIABLE_SRC', '')) if pd.notna(row.get('MATCHED_VARIABLE_SRC')) else None,
                    "matched_variable_name": str(row.get('MATCHED_VARIABLE_NAME', '')) if pd.notna(row.get('MATCHED_VARIABLE_NAME')) else None,
                    "matched_variable_value": str(row.get('MATCHED_VARIABLE_VALUE', '')) if pd.notna(row.get('MATCHED_VARIABLE_VALUE')) else None
                }
                samples.append(sample)
            except Exception as e:
                print(f"Пропускаем строку {idx}: {e}")
                continue
        
        results = []
        batch_size = 100
        
        for i in range(0, len(samples), batch_size):
            batch = samples[i:i+batch_size]
            try:
                batch_results = self.predict_batch(batch)
                results.extend(batch_results)
                print(f"Обработано {min(i+batch_size, len(samples))}/{len(samples)}")
            except Exception as e:
                print(f"Ошибка на батче {i}: {e}")
                for sample in batch:
                    results.append({
                        "event_id": sample["event_id"],
                        "label_pred": -1,
                        "probability": 0.0,
                        "is_attack": False,
                        "error": str(e)
                    })
        
        return pd.DataFrame(results)


if __name__ == "__main__":
    
    client = WAFClient("http://localhost:8000")
    
    #Проверяем, что сервис работает
    print("\n=== Проверка сервиса ===")
    try:
        health = client.check_health()
        print(f"Статус: {health['status']}")
        print(f"Порог: {health['threshold']}")
    except Exception as e:
        print(f"Сервис недоступен: {e}")
        print("Запустите сначала сервер: python inferences.py")
        sys.exit(1)
    
    # Тестовые запросы
    print("\n=== Тестовые запросы ===")
    
    # Нормальный запрос
    result = client.predict_single(
        event_id="test_normal_1",
        matched_variable_value="page=home",
        client_useragent="Mozilla/5.0 Chrome"
    )
    print(f"Нормальный: атака={result['is_attack']}, вероятность={result['probability']:.4f}")
    
    # SQL-инъекция
    result = client.predict_single(
        event_id="test_sqli_1",
        matched_variable_value="1' UNION SELECT * FROM users--",
        client_useragent="Mozilla/5.0"
    )
    print(f"SQLi: атака={result['is_attack']}, вероятность={result['probability']:.4f}")
    
    # XSS
    result = client.predict_single(
        event_id="test_xss_1",
        matched_variable_value="<script>alert(1)</script>",
        client_useragent="Mozilla/5.0"
    )
    print(f"XSS: атака={result['is_attack']}, вероятность={result['probability']:.4f}")
    
    # Path Traversal
    result = client.predict_single(
        event_id="test_path_traversal",
        matched_variable_value="../../etc/passwd",
        client_useragent="sqlmap/1.0"
    )
    print(f"Path Traversal: атака={result['is_attack']}, вероятность={result['probability']:.4f}")
    
    # 3. Тест из CSV
    print("\n=== Тест из CSV ===")
    try:
        results_df = client.test_with_csv("http.csv", limit=100)
        print(f"Обработано записей: {len(results_df)}")
        print(f"Обнаружено атак: {results_df['is_attack'].sum()}")
        print(f"Нормальных: {(~results_df['is_attack']).sum()}")
        print("\nПримеры результатов:")
        print(results_df[['event_id', 'label_pred', 'probability', 'is_attack']].head(10))
    except FileNotFoundError:
        print("CSV файл не найден.")