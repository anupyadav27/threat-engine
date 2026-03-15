FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY engines/compliance/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy compliance engine code (destination paths match Python imports)
COPY engines/compliance/compliance_engine/ ./compliance_engine/
COPY engines/compliance/data/ ./data/

# Copy shared utilities
COPY shared/common/ ./engine_common/
COPY shared/database/ ./consolidated_services/

ENV PYTHONPATH=/app

# Expose port
EXPOSE 8010

# Run API server
CMD ["uvicorn", "compliance_engine.api_server:app", "--host", "0.0.0.0", "--port", "8010"]
