FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
# Note: Build context is repo root, so paths are relative to root
COPY engines/discoveries/engine_discoveries_aws/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy all necessary files from engine_discoveries_aws
COPY engines/discoveries/engine_discoveries_aws/engine/ ./engine/
COPY engines/discoveries/engine_discoveries_aws/auth/ ./auth/
COPY engines/discoveries/engine_discoveries_aws/utils/ ./utils/
COPY engines/discoveries/engine_discoveries_aws/services/ ./services/
COPY engines/discoveries/engine_discoveries_aws/config/ ./config/
COPY engines/discoveries/engine_discoveries_aws/database/ ./database/
COPY engines/discoveries/engine_discoveries_aws/api_server.py .
# Also copy the common database module (used for resource_arn consolidation)
COPY engines/discoveries/common/ ./common/
# Shared utilities (destination matches Python imports: engine_common.*)
COPY shared/common/ ./engine_common/
COPY engines/onboarding/storage/ ./engine_onboarding/storage/
COPY engines/onboarding/__init__.py ./engine_onboarding/

# Set Python path
ENV PYTHONPATH=/app

# Allow PORT to be configured via environment variable
ENV PORT=8001

# Expose port
EXPOSE ${PORT}

# Run API server with configurable port
CMD ["sh", "-c", "uvicorn api_server:app --host 0.0.0.0 --port ${PORT:-8001} --timeout-keep-alive 75"]
