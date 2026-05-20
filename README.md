# WAF ML Service

Сервис на основе машинного обучения для классификации вредоносных веб-запросов. Проект выполнен в рамках тестового задания.

## Описание

Сервис анализирует HTTP-запросы и определяет, является ли запрос атакой (SQL-инъекция, XSS, Path Traversal, Command Injection) или легитимным трафиком.

### Основные возможности

- Бинарная классификация запросов (атака / норма)
- Многоклассовая классификация типов атак
- Защита от evasion-атак (устойчивые признаки)
- Пакетная обработка запросов
- REST API (FastAPI)
- Docker-контейнеризация

### Данные
- Логи Web Application Firewall (WAF)
- Размеченные данные: нормальные запросы и атаки
- Признаки: текстовые (payload), числовые (размер, энтропия), бинарные (SQL-паттерны, XSS, Path Traversal)

### Метрики
| Метрика | Значение |
|---------|----------|
| ROC-AUC | 0.9997 |
| Recall (атаки) | 0.99 |
| Precision (атаки) | 0.90 |
| False Positive Rate | 0.6% |

### Feature Engineering
- TF-IDF векторизация текста (ngram_range=1-3)
- Энтропия Шеннона для payload
- Regex-паттерны (SQL, XSS, Path Traversal, Command Injection)
- Анализ User-Agent (боты, тулзы)
- Числовые признаки (размер запроса, код ответа)

### Защита от Evasion-атак
- Case-insensitive паттерны
- Нормализация URL-encoding
- Комбинаторные признаки (ngrams)
- Кастомный порог классификации

## API Endpoints

| Метод | URL | Описание |
|-------|-----|----------|
| GET | `/health` | Проверка работоспособности |
| POST | `/predict` | Классификация одного запроса |
| POST | `/predict_batch` | Пакетная классификация |
| GET | `/docs` | Swagger UI |

### Пример запроса

```json
POST /predict
{
    "event_id": "test_001",
    "client_useragent": "Mozilla/5.0",
    "matched_variable_value": "1' UNION SELECT * FROM users--",
    "request_size": 300,
    "response_code": 404
}
{
    "event_id": "test_001",
    "label_pred": 1,
    "probability": 0.9799,
    "is_attack": true
}
