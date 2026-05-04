# =============================================================================
# Platform Admin Engine — Operator dashboard, engine health, org management
# Port: 8041
# Build context: REPO ROOT (docker build -f engines/platform-admin/Dockerfile .)
# =============================================================================

FROM python:3.11-slim AS builder

WORKDIR /app
COPY engines/platform-admin/requirements.txt .
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
COPY engines/platform-admin/ /app/

# Non-root user (SLSA Level 1 best practice)
RUN useradd -r -s /bin/false appuser
USER appuser

EXPOSE 8041

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8041"]
