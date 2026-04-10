FROM python:3.9-slim

WORKDIR /app

# Install dependencies
COPY engines/encryption-security/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY engines/encryption-security/encryption_security_engine/ ./encryption_security_engine/

# Run scan entry point (for K8s Job execution)
COPY engines/encryption-security/run_scan.py ./run_scan.py

# Copy shared utilities
COPY shared/common/ ./engine_common/
COPY shared/database/ ./consolidated_services/

# Set environment variables
ENV PYTHONPATH=/app
ENV PORT=8006

# Expose port
EXPOSE 8006

# Run API server
CMD ["python", "-m", "uvicorn", "encryption_security_engine.api_server:app", "--host", "0.0.0.0", "--port", "8006"]
