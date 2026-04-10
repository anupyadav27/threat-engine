FROM python:3.9-slim

WORKDIR /app

# Install dependencies
COPY engines/ai-security/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY engines/ai-security/ai_security_engine/ ./ai_security_engine/

# Run scan entry point (for K8s Job execution)
COPY engines/ai-security/run_scan.py ./run_scan.py

# Copy shared utilities
COPY shared/common/ ./engine_common/
COPY shared/database/ ./consolidated_services/

# Set environment variables
ENV PYTHONPATH=/app
ENV PORT=8032

# Expose port
EXPOSE 8032

# Run API server
CMD ["python", "-m", "uvicorn", "ai_security_engine.api_server:app", "--host", "0.0.0.0", "--port", "8032"]
