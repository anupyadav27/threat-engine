FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY engines/rule/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY engines/rule/ ./

ENV PYTHONPATH=/app

EXPOSE 8000

CMD ["uvicorn", "api_server:app", "--host", "0.0.0.0", "--port", "8000"]
