FROM python:3.11-slim AS base

WORKDIR /app

# Install dependencies
COPY engines/network-security/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy shared libraries
COPY shared/common/ /app/common/
COPY shared/database/ /app/database/

# Copy engine code
COPY engines/network-security/ /app/

# Non-root user
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8004

# Default: run API server (override with --scan-run-id for K8s Job mode)
CMD ["python", "-m", "network_security_engine.api_server"]
