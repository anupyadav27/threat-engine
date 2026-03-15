# =============================================================================
# Log Collector Service — Dockerfile
# Task 0.2.11 [Seq 23 | DO]
# =============================================================================
# Multi-stage build for the log collector service (Tier 2)
# Entrypoint is configurable: api_server.py or sqs_worker.py
# =============================================================================

# ---------- Stage 1: Builder ----------
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY shared/log_collector/requirements.txt /build/requirements.txt
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ---------- Stage 2: Runtime ----------
FROM python:3.11-slim

# Security: create non-root user
RUN groupadd -r logcollector && useradd -r -g logcollector -d /app -s /sbin/nologin logcollector

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

WORKDIR /app

# Copy application code
COPY shared/log_collector/ /app/shared/log_collector/
COPY shared/common/ /app/shared/common/
COPY shared/database/ /app/shared/database/

# Ensure Python can find shared modules
ENV PYTHONPATH="/app"
ENV PYTHONUNBUFFERED=1

# Default environment variables
ENV TH_LOG_COLLECTOR_PORT=8030
ENV LOG_COLLECTOR_DB_HOST=localhost
ENV LOG_COLLECTOR_DB_PORT=5432
ENV LOG_COLLECTOR_DB_NAME=threat_engine_logs
ENV LOG_COLLECTOR_DB_USER=postgres

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:${TH_LOG_COLLECTOR_PORT}/api/v1/health/live || exit 1

# Switch to non-root user
USER logcollector

# Default entrypoint: API server
# Override with CMD ["python", "-m", "shared.log_collector.sqs_worker"] for SQS worker
EXPOSE 8030
CMD ["python", "-m", "shared.log_collector.api_server"]
