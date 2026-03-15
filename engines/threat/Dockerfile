FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY engines/threat/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code (destination paths match Python imports)
COPY engines/threat/threat_engine/ ./threat_engine/
COPY shared/common/ ./engine_common/
COPY shared/database/ ./consolidated_services/
ENV PYTHONPATH=/app

# Expose port
EXPOSE 8020

# Run API server
CMD ["python", "-m", "uvicorn", "threat_engine.api_server:app", "--host", "0.0.0.0", "--port", "8020"]
