FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY api_gateway/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY api_gateway/*.py ./
COPY api_gateway/ ./
COPY engine_common/ ./engine_common

# Create non-root user
RUN groupadd -r gateway && useradd -r -g gateway gateway
RUN chown -R gateway:gateway /app
USER gateway

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/gateway/health || exit 1

# Run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]