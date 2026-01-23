FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY compliance-engine/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy compliance engine code
COPY compliance-engine/compliance_engine/ ./compliance_engine/
COPY compliance-engine/data/ ./data/

# Copy compliance mappings (for framework loader fallback)
COPY compliance/ ./compliance/

# Copy API server
COPY compliance-engine/compliance_engine/api_server.py .

# Set Python path
ENV PYTHONPATH=/app

# Expose port
EXPOSE 8000

# Run API server
CMD ["uvicorn", "compliance_engine.api_server:app", "--host", "0.0.0.0", "--port", "8000"]
