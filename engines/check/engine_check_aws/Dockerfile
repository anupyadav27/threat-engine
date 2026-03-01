FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
# Note: Build context is root, so paths are relative to root
COPY engine_check/engine_check_aws/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy all necessary files from engine_check_aws
COPY engine_check/engine_check_aws/engine/ ./engine/
COPY engine_check/engine_check_aws/auth/ ./auth/
COPY engine_check/engine_check_aws/utils/ ./utils/
COPY engine_check/engine_check_aws/services/ ./services/
# Also copy into repo-relative path expected by runtime code:
# /app/engine_check/engine_check_aws/services/<service>/checks/...
RUN mkdir -p /app/engine_check/engine_check_aws
COPY engine_check/engine_check_aws/services/ ./engine_check/engine_check_aws/services/
COPY engine_check/engine_check_aws/config/ ./config/
COPY engine_check/engine_check_aws/database/ ./database/
COPY engine_check/engine_check_aws/api_server.py .
COPY engine_common/ ./engine_common/

# Set Python path
ENV PYTHONPATH=/app

# Allow PORT to be configured via environment variable
ENV PORT=8002

# Expose port
EXPOSE ${PORT}

# Run API server with configurable port
CMD ["sh", "-c", "uvicorn api_server:app --host 0.0.0.0 --port ${PORT:-8002} --timeout-keep-alive 75"]
