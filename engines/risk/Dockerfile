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

# Copy shared utilities
COPY shared/common/ shared/common/

# Copy engine code
COPY engines/risk/ engines/risk/

# Non-root user
RUN useradd -r -s /bin/false appuser
USER appuser

EXPOSE 8009

ENTRYPOINT ["python", "-m", "engines.risk.api_server"]
