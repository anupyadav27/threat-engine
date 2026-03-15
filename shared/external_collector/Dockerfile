# ---------------------------------------------------------------------------
# External Collector — Task 0.3.15 [Seq 39 | DO]
# Multi-stage Docker build with embedded Trivy binary.
# ---------------------------------------------------------------------------

# Stage 1: Builder
FROM python:3.11-slim AS builder

WORKDIR /build

COPY shared/external_collector/requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Download Trivy binary
ARG TRIVY_VERSION=0.50.4
RUN apt-get update && apt-get install -y --no-install-recommends curl tar \
    && curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
       | tar -xzf - -C /usr/local/bin trivy \
    && chmod +x /usr/local/bin/trivy \
    && apt-get purge -y curl tar && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# Stage 2: Runtime
FROM python:3.11-slim AS runtime

# Create non-root user
RUN groupadd -r collector && useradd -r -g collector -d /app -s /sbin/nologin collector

WORKDIR /app

# Copy Python packages
COPY --from=builder /install /usr/local

# Copy Trivy binary
COPY --from=builder /usr/local/bin/trivy /usr/local/bin/trivy

# Copy application code
COPY shared/external_collector/ /app/shared/external_collector/
COPY shared/common/ /app/shared/common/
COPY shared/database/ /app/shared/database/

# Create Trivy cache directory
RUN mkdir -p /tmp/trivy-cache && chown collector:collector /tmp/trivy-cache

# Set environment
ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1 \
    TRIVY_CACHE_DIR=/tmp/trivy-cache \
    TH_EXTERNAL_COLLECTOR_PORT=8031

# Switch to non-root
USER collector

EXPOSE 8031

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8031/api/v1/health/live')"

ENTRYPOINT ["python", "-m", "shared.external_collector.api_server"]
