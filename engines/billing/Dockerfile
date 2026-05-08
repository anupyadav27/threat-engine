# =============================================================================
# Billing Engine — Subscription plans, usage metering, trial lifecycle
# Port: 8040
# Build context: REPO ROOT (docker build -f engines/billing/Dockerfile .)
# =============================================================================

FROM python:3.11-slim AS builder

WORKDIR /app
COPY engines/billing/requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# -----------------------------------------------------------------------------
FROM python:3.11-slim

WORKDIR /app
COPY --from=builder /install /usr/local

# Shared auth utilities (available as engine_auth/ inside the container)
COPY shared/auth/ /app/engine_auth/

# Shared common utilities (available as engine_common/ inside the container)
COPY shared/common/ /app/engine_common/

# Engine source
COPY engines/billing/ /app/

# Non-root user (SLSA Level 1 best practice)
RUN useradd -r -s /bin/false appuser
USER appuser

EXPOSE 8040

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8040"]
