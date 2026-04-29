# Dockerfile for SBOM Engine
# Build context: project root (d:/Project/Vulnerability)
# docker build -f sbom_engine/Dockerfile -t ajaychaudhary86/sbom_engine:latest .

FROM python:3.11-slim

WORKDIR /app

# Copy the entire project so core/ and sbom_engine/ are both available
COPY . /app/

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir -r sbom_engine/requirements.txt

ENV DB_HOST=postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com \
    DB_PORT=5432 \
    DB_NAME=vulnerability_db \
    DB_USER=postgres \
    PORT=8002

ENV PYTHONPATH="/app/sbom_engine:/app"

CMD ["python", "sbom_engine/main.py"]
