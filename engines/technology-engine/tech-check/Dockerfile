FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY engines/technology-engine/tech-check/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/common /app/engine_common
COPY engines/technology-engine/tech-discovery/common /app/common

COPY engines/technology-engine/tech-check /app

COPY catalog /app/../catalog

ENV PYTHONPATH=/app

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8032"]
