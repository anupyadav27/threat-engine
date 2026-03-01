FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
# Note: Build context is root, so paths are relative to root
COPY engine_discoveries/engine_discoveries_aws/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy all necessary files from engine_discoveries_aws
COPY engine_discoveries/engine_discoveries_aws/engine/ ./engine/
COPY engine_discoveries/engine_discoveries_aws/auth/ ./auth/
COPY engine_discoveries/engine_discoveries_aws/utils/ ./utils/
COPY engine_discoveries/engine_discoveries_aws/services/ ./services/
COPY engine_discoveries/engine_discoveries_aws/config/ ./config/
COPY engine_discoveries/engine_discoveries_aws/database/ ./database/
COPY engine_discoveries/engine_discoveries_aws/api_server.py .
COPY engine_common/ ./engine_common/
COPY engine_onboarding/storage/ ./engine_onboarding/storage/
COPY engine_onboarding/__init__.py ./engine_onboarding/

# Set Python path
ENV PYTHONPATH=/app

# Allow PORT to be configured via environment variable
ENV PORT=8001

# Expose port
EXPOSE ${PORT}

# Run API server with configurable port
CMD ["sh", "-c", "uvicorn api_server:app --host 0.0.0.0 --port ${PORT:-8001} --timeout-keep-alive 75"]
