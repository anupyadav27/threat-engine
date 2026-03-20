FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY engines/discoveries/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy multi-cloud provider code
COPY engines/discoveries/providers/ ./providers/

# Copy common layer (api_server, database, orchestration, models, utils)
COPY engines/discoveries/common/ ./common/

# Copy shared discovery utils (config_loader, filter_engine, pagination_engine)
COPY engines/discoveries/utils/ ./utils/

# Copy Job entry point (used by K8s Jobs for on-demand scans)
COPY engines/discoveries/run_scan.py ./run_scan.py

# Shared utilities (destination matches Python imports: engine_common.*)
COPY shared/common/ ./engine_common/

# Shared database (orchestration_client, schemas — import as consolidated_services.*)
COPY shared/database/ ./consolidated_services/

# Onboarding storage + config (credential fetcher needs config.settings)
COPY engines/onboarding/storage/ ./engine_onboarding/storage/
COPY engines/onboarding/__init__.py ./engine_onboarding/
COPY engines/onboarding/config.py ./engine_onboarding/

# Set Python path
ENV PYTHONPATH=/app
ENV PORT=8001

EXPOSE ${PORT}

CMD ["sh", "-c", "uvicorn common.api_server:app --host 0.0.0.0 --port ${PORT:-8001} --timeout-keep-alive 75"]
