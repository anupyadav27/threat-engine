# ── Stage 1: builder ──────────────────────────────────────────────────────────
# SLSA Level 1-2: pinned base image (no :latest per CP1-08)
FROM python:3.11-slim-bookworm AS builder

WORKDIR /build

# Install dependencies into a prefix directory so they can be copied cleanly
COPY engines/threat_v1/requirements.txt /build/requirements.txt
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM python:3.11-slim-bookworm AS runtime

# Non-root user (mandatory security requirement)
RUN useradd -m -u 1001 threatv1

WORKDIR /app

# Copy installed packages from builder stage
COPY --from=builder /install /usr/local

# Copy application code
# Build context is REPO ROOT: docker build -f engines/threat_v1/Dockerfile .
COPY engines/threat_v1/requirements.txt /app/requirements.txt
COPY shared/common/ /app/engine_common/
COPY shared/auth/ /app/engine_auth/
COPY engines/threat_v1/threat_v1/ /app/threat_v1/
COPY engines/threat_v1/run_scan.py /app/run_scan.py
COPY engines/threat_v1/main.py /app/main.py
COPY engines/threat_v1/catalog/ /app/catalog/
COPY engines/threat_v1/scripts/ /app/scripts/

ENV PYTHONPATH=/app

EXPOSE 8021

# Switch to non-root user
USER threatv1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8021"]
