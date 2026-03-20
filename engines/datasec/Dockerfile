FROM python:3.9-slim

WORKDIR /app

# Install dependencies
COPY engines/datasec/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code (destination paths match Python imports)
COPY engines/datasec/data_security_engine/ ./data_security_engine/
COPY engines/datasec/config/ ./config/
COPY engines/datasec/scripts/ ./scripts/

# Run scan entry point (for K8s Job execution)
COPY engines/datasec/run_scan.py ./run_scan.py

COPY shared/common/ ./engine_common/
COPY shared/database/ ./consolidated_services/

# Set environment variables
ENV PYTHONPATH=/app
ENV PORT=8004

# Expose port
EXPOSE 8004

# Run API server
CMD ["python", "-m", "uvicorn", "data_security_engine.api_server:app", "--host", "0.0.0.0", "--port", "8004"]
