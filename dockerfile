FROM python:3.12-slim

WORKDIR /app

# Установка точно таких же версий как у вас локально
RUN pip install --no-cache-dir \
    numpy==2.2.6 \
    scikit-learn==1.6.1 \
    joblib==1.4.2 \
    pandas==2.2.3 \
    fastapi==0.115.6 \
    uvicorn[standard]==0.34.0 \
    pydantic==2.10.3 \
    python-multipart==0.0.18 \
    requests==2.32.3

COPY inferences.py .
COPY client.py .
COPY models/ ./models/

EXPOSE 8000

CMD ["python", "inferences.py"]