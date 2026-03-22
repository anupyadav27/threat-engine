FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY engines/check/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# ── Common layer (CSP-agnostic) ───────────────────────────────────────────────
COPY engines/check/common/ ./common/

# ── Providers layer (CSP-specific evaluators) ─────────────────────────────────
COPY engines/check/providers/ ./providers/

# ── Legacy engine_check_aws (YAML rule files, utils, config) ──────────────────
# The check engine loads YAML check/discovery definitions from:
#   engine_check/engine_check_aws/services/<service>/checks/
#   engine_check/engine_check_aws/services/<service>/discoveries/
# Keep these available so the engine can merge YAML base rules with DB rules.
COPY engines/check/engine_check_aws/services/ ./engine_check/engine_check_aws/services/
COPY engines/check/engine_check_aws/utils/    ./engine_check/engine_check_aws/utils/
COPY engines/check/engine_check_aws/config/   ./engine_check/engine_check_aws/config/

# ── Run scan entry point (for K8s Job execution) ───────────────────────────
COPY engines/check/run_scan.py ./run_scan.py

# ── Shared utilities (destination matches Python imports: engine_common.*) ────
COPY shared/common/ ./engine_common/

# ── Consolidated services (orchestration_client) ──────────────────────────────
COPY shared/database/ ./consolidated_services/database/
RUN echo "# consolidated_services package" > ./consolidated_services/__init__.py

# ── Python path ───────────────────────────────────────────────────────────────
ENV PYTHONPATH=/app

# Port configuration — check engine runs on 8002
ENV PORT=8002
EXPOSE ${PORT}

# Liveness / readiness probes hit /api/v1/health/live
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:${PORT:-8002}/api/v1/health/live')" || exit 1

# Run the multi-CSP API server
CMD ["sh", "-c", "uvicorn common.api_server:app --host 0.0.0.0 --port ${PORT:-8002} --timeout-keep-alive 75 --log-level info"]
