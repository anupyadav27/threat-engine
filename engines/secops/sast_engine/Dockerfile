FROM python:3.11-slim

LABEL maintainer="SecOps Team"
LABEL description="Unified code security platform — SAST (14 languages), DAST (OWASP Top 10), SCA/SBOM"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (for better caching)
COPY engines/secops/sast_engine/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy SAST engine (main app, routers, scanners, database)
COPY engines/secops/sast_engine/ .

# Copy DAST engine (separate package)
COPY engines/secops/dast_engine/ ./dast_engine/

# Copy SCA/SBOM engine (separate package)
COPY engines/secops/sca_sbom_engine/ ./sca_sbom_engine/

# Copy shared utilities
COPY shared/common/ ./engine_common/

# Create input/output folders
RUN mkdir -p /app/scan_input /app/scan_output

# Set environment variables
ENV SCAN_INPUT_PATH=/app/scan_input
ENV SCAN_OUTPUT_PATH=/app/scan_output
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV SECOPS_PORT=8009

# Expose API port
EXPOSE 8009

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8009/health || exit 1

# Run API server
CMD ["uvicorn", "api_server:app", "--host", "0.0.0.0", "--port", "8009", "--workers", "2"]
