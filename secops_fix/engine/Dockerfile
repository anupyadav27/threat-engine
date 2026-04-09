FROM python:3.11-slim AS base

WORKDIR /app

# ── System dependencies ────────────────────────────────────────────────────────
# libpq-dev + gcc + build-essential — compile psycopg2 from source (production-safe)
# git — required by gitpython for repo clone + push
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq-dev \
        gcc \
        build-essential \
        git \
    && rm -rf /var/lib/apt/lists/*

# ── Python dependencies ────────────────────────────────────────────────────────
COPY engine/requirements.txt .

# Compile psycopg2 from source — binary wheel bundles private libpq, not recommended
# for production. Remove psycopg2-binary from requirements and install compiled version.
RUN pip install --no-cache-dir \
        psycopg2==2.9.9 \
    && grep -v "psycopg2" requirements.txt > /tmp/req_no_psycopg2.txt \
    && pip install --no-cache-dir -r /tmp/req_no_psycopg2.txt \
    && rm /tmp/req_no_psycopg2.txt

# ── Application source ─────────────────────────────────────────────────────────
COPY engine/ .

# ── Non-root user — reduce attack surface ─────────────────────────────────────
# Purge build tools after psycopg2 compilation to shrink the image attack surface
RUN apt-get purge -y --auto-remove gcc build-essential \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 1001 -s /bin/bash secopsfix \
    && chown -R secopsfix:secopsfix /app

USER secopsfix

EXPOSE 8006

ENV SECOPS_FIX_PORT=8006 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

# ── Required secrets (injected via Kubernetes secrets) ────────────────────────
# SECOPS_FIX_API_KEY       — API key clients must send in X-API-Key header
# MISTRAL_API_KEY           — Mistral AI key for code fix generation
# DB_HOST / DB_PORT / DB_NAME / DB_USER / DB_PASSWORD — threat_engine_secops RDS
# (repo_token is passed per-request in X-Repo-Token header — never stored)

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8006/api/v1/health/live')"

# workers=1 is REQUIRED — asyncio.Semaphore lives in one process.
# Multiple workers would give each process its own independent semaphore,
# making the concurrency limit (SECOPS_FIX_MAX_CONCURRENT) ineffective.
# Scale horizontally via Kubernetes replicas, not uvicorn workers.
CMD ["python", "-m", "uvicorn", "api_server:app", \
     "--host", "0.0.0.0", \
     "--port", "8006", \
     "--workers", "1", \
     "--log-level", "info"]
