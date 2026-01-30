FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y gcc && rm -rf /var/lib/apt/lists/*

COPY engine_configscan/engine_configscan_alicloud/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY engine_configscan/engine_configscan_alicloud/engine/ ./engine/
COPY engine_configscan/engine_configscan_alicloud/auth/ ./auth/
COPY engine_configscan/engine_configscan_alicloud/utils/ ./utils/
COPY engine_configscan/engine_configscan_alicloud/services/ ./services/
COPY engine_configscan/engine_configscan_alicloud/config/ ./config/
COPY engine_configscan/engine_configscan_alicloud/api_server.py .
COPY engine_common/ ./engine_common/

ENV PYTHONPATH=/app
EXPOSE 8000
CMD ["uvicorn", "api_server:app", "--host", "0.0.0.0", "--port", "8000"]
