FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY engine_rule/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy rule engine code
COPY engine_rule/ ./engine_rule/
COPY data_pythonsdk/ ./pythonsdk-database/

# Set Python path
ENV PYTHONPATH=/app:/app/engine_rule

# Expose port
EXPOSE 8000

# Run API server
WORKDIR /app/engine_rule
CMD ["uvicorn", "api_server:app", "--host", "0.0.0.0", "--port", "8000"]
