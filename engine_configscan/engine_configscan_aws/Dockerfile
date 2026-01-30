FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
# Note: Build context is root, so paths are relative to root
COPY engine_configscan/engine_configscan_aws/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy all necessary files from engine_configscan_aws
COPY engine_configscan/engine_configscan_aws/engine/ ./engine/
COPY engine_configscan/engine_configscan_aws/auth/ ./auth/
COPY engine_configscan/engine_configscan_aws/utils/ ./utils/
COPY engine_configscan/engine_configscan_aws/services/ ./services/
COPY engine_configscan/engine_configscan_aws/config/ ./config/
COPY engine_configscan/engine_configscan_aws/database/ ./database/
COPY engine_configscan/engine_configscan_aws/api_server.py .
COPY engine_common/ ./engine_common/
# Set Python path
ENV PYTHONPATH=/app

# Allow PORT to be configured via environment variable
ENV PORT=8000

# Expose port
EXPOSE ${PORT}

# Run API server with configurable port
# Keep-alive is increased to reduce premature connection closes under load.
CMD ["sh", "-c", "uvicorn api_server:app --host 0.0.0.0 --port ${PORT:-8000} --timeout-keep-alive 75"]
