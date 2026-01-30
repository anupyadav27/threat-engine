FROM python:3.11-slim

LABEL maintainer="SecOps Team"
LABEL description="Vulnerability Scanner API for Python and Terraform"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (for better caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install FastAPI dependencies
RUN pip install --no-cache-dir \
    fastapi==0.104.1 \
    uvicorn[standard]==0.24.0 \
    python-multipart==0.0.6 \
    pydantic==2.5.0

# Copy application code
COPY . .

# Create input/output folders
RUN mkdir -p /app/scan_input /app/scan_output

# Set environment variables
ENV SCAN_INPUT_PATH=/app/scan_input
ENV SCAN_OUTPUT_PATH=/app/scan_output
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Expose API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run API server
CMD ["uvicorn", "api_server:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]

