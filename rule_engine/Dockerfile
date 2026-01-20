FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY yaml-rule-builder/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy rule builder code
COPY yaml-rule-builder/ ./yaml-rule-builder/
COPY pythonsdk-database/ ./pythonsdk-database/

# Copy API server
COPY yaml-rule-builder/api_server.py .

# Set Python path to include both /app and /app/yaml-rule-builder
ENV PYTHONPATH=/app:/app/yaml-rule-builder

# Expose port
EXPOSE 8000

# Run API server from yaml-rule-builder directory
WORKDIR /app/yaml-rule-builder
CMD ["uvicorn", "api_server:app", "--host", "0.0.0.0", "--port", "8000"]
