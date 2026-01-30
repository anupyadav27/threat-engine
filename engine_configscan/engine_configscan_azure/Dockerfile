FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements (build context = repo root)
COPY engine_configscan/engine_configscan_azure/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy engine code
COPY engine_configscan/engine_configscan_azure/engine/ ./engine/
COPY engine_configscan/engine_configscan_azure/auth/ ./auth/
COPY engine_configscan/engine_configscan_azure/utils/ ./utils/
COPY engine_configscan/engine_configscan_azure/services/ ./services/
COPY engine_configscan/engine_configscan_azure/config/ ./config/
COPY engine_configscan/engine_configscan_azure/api_server.py .
COPY engine_common/ ./engine_common/

# Set Python path
ENV PYTHONPATH=/app

# Expose port
EXPOSE 8000

# Run API server
CMD ["uvicorn", "api_server:app", "--host", "0.0.0.0", "--port", "8000"]

