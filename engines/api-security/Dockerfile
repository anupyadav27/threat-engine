FROM python:3.11.9-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev gcc \
    && rm -rf /var/lib/apt/lists/*

COPY shared/common/ /app/engine_common/
COPY shared/auth/ /app/engine_auth/

COPY engines/api-security/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY engines/api-security/ .

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

EXPOSE 8035

CMD ["uvicorn", "api_server:app", "--host", "0.0.0.0", "--port", "8035", "--workers", "1"]
