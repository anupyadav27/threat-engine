FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y gcc && rm -rf /var/lib/apt/lists/*

COPY engine_configscan/engine_configscan_oci/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY engine_configscan/engine_configscan_oci/engine/ ./engine/
COPY engine_configscan/engine_configscan_oci/auth/ ./auth/
COPY engine_configscan/engine_configscan_oci/utils/ ./utils/
COPY engine_configscan/engine_configscan_oci/services/ ./services/
COPY engine_configscan/engine_configscan_oci/api_server.py .
COPY engine_common/ ./engine_common/

ENV PYTHONPATH=/app
EXPOSE 8000
CMD ["uvicorn", "api_server:app", "--host", "0.0.0.0", "--port", "8000"]
