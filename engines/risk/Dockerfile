# =============================================================================
# Risk Engine — FAIR Model Financial Risk Quantification
# Port: 8009
# =============================================================================

FROM python:3.11-slim AS builder

WORKDIR /app
COPY engines/risk/requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# -----------------------------------------------------------------------------
FROM python:3.11-slim

WORKDIR /app
COPY --from=builder /install /usr/local

# Copy shared utilities (available as both shared/common/ and engine_common/)
COPY shared/common/ shared/common/
COPY shared/common/ engine_common/
COPY shared/auth/ engine_auth/

# Copy engine code
COPY engines/risk/ engines/risk/

# Copy run_scan entry point to root so `python -m run_scan` works for K8s Jobs
COPY engines/risk/run_scan.py ./run_scan.py

# Non-root user
RUN useradd -r -s /bin/false appuser
USER appuser

EXPOSE 8009

ENTRYPOINT ["python", "-m", "engines.risk.api_server"]
