FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
# Note: Build context is root, so paths are relative to root
COPY aws_compliance_python_engine/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy all necessary files from aws_compliance_python_engine directory
COPY aws_compliance_python_engine/engine/ ./engine/
COPY aws_compliance_python_engine/auth/ ./auth/
COPY aws_compliance_python_engine/utils/ ./utils/
COPY aws_compliance_python_engine/services/ ./services/
COPY aws_compliance_python_engine/config/ ./config/
COPY aws_compliance_python_engine/api_server.py .

# Set Python path
ENV PYTHONPATH=/app

# Allow PORT to be configured via environment variable
ENV PORT=8000

# Expose port
EXPOSE ${PORT}

# Run API server with configurable port
# Keep-alive is increased to reduce premature connection closes under load.
CMD ["sh", "-c", "uvicorn api_server:app --host 0.0.0.0 --port ${PORT:-8000} --timeout-keep-alive 75"]
