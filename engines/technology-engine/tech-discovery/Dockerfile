FROM python:3.12-slim

WORKDIR /app

# System deps for DB connectors and SSH
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpq-dev openssh-client unixodbc-dev \
    && rm -rf /var/lib/apt/lists/*

COPY engines/technology-engine/tech-discovery/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Shared libraries
COPY shared/common /app/engine_common
COPY engines/onboarding /app/engine_onboarding

# Engine code
COPY engines/technology-engine/tech-discovery /app

# Catalog YAMLs
COPY catalog /app/../catalog

ENV PYTHONPATH=/app

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8030"]
