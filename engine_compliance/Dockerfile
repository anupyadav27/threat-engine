FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY engine_compliance/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy compliance engine code
COPY engine_compliance/compliance_engine/ ./compliance_engine/
COPY engine_compliance/data/ ./data/

# Copy engine_common
COPY engine_common/ ./engine_common/

# Copy consolidated_services
COPY consolidated_services/ ./consolidated_services/

# Copy API server
COPY engine_compliance/compliance_engine/api_server.py .

ENV PYTHONPATH=/app

# Expose port
EXPOSE 8010

# Run API server
CMD ["uvicorn", "compliance_engine.api_server:app", "--host", "0.0.0.0", "--port", "8010"]
