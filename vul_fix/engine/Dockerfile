FROM python:3.11-slim AS base

# ── Build args ────────────────────────────────────────────────────────────────
ARG ANSIBLE_CORE_VERSION=2.17.7
ARG ANSIBLE_LINT_VERSION=24.9.2

WORKDIR /app

# ── System dependencies ───────────────────────────────────────────────────────
# libpq-dev   — compile psycopg2 from source (production-safe, no binary quirks)
# git         — required by gitpython for cloning Ansible repos
# openssh-client — SSH fallback for git (optional; HTTPS is primary)
# gcc / build-essential — compile psycopg2
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq-dev \
        gcc \
        build-essential \
        git \
        openssh-client \
    && rm -rf /var/lib/apt/lists/*

# ── Python dependencies ───────────────────────────────────────────────────────
COPY engine/requirements.txt .

# Replace psycopg2-binary with compiled psycopg2 for production
RUN pip install --no-cache-dir \
        psycopg2==2.9.9 \
    && grep -v "psycopg2" requirements.txt > /tmp/req_no_psycopg2.txt \
    && pip install --no-cache-dir -r /tmp/req_no_psycopg2.txt \
    && rm /tmp/req_no_psycopg2.txt

# ── Ansible tools (Layer 2 validator) ────────────────────────────────────────
# Installed separately so Docker layer cache is reused when only app code changes.
# ansible-lint requires ansible-core on PATH.
RUN pip install --no-cache-dir \
        "ansible-core==${ANSIBLE_CORE_VERSION}" \
        "ansible-lint==${ANSIBLE_LINT_VERSION}"

# Verify ansible-lint is reachable (fail build if install broken)
RUN ansible-lint --version 2>&1 | head -1

# ── Application source ────────────────────────────────────────────────────────
COPY engine/ .

# ── Non-root user ─────────────────────────────────────────────────────────────
# Remove build tools after compilation — reduce attack surface
RUN apt-get purge -y --auto-remove gcc build-essential \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 1001 -s /bin/bash vulfixuser \
    && chown -R vulfixuser:vulfixuser /app

USER vulfixuser

# ── Git identity for commits ──────────────────────────────────────────────────
# Required for git commit inside GitPusher; overridden by Kubernetes env vars
ENV GIT_AUTHOR_NAME="VulFix Engine" \
    GIT_AUTHOR_EMAIL="vulfix@noreply.local" \
    GIT_COMMITTER_NAME="VulFix Engine" \
    GIT_COMMITTER_EMAIL="vulfix@noreply.local"

EXPOSE 8007

ENV VUL_FIX_PORT=8007 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

# ── Required secrets (injected via Kubernetes secrets) ────────────────────────
# VUL_DB_HOST       — RDS hostname
# VUL_DB_PORT       — default 5432
# VUL_DB_NAME       — vulnerability_db
# VUL_DB_USER       — postgres
# VUL_DB_PASSWORD   — from K8s secret
# MISTRAL_API_KEY   — Mistral AI key
# GIT_TOKEN         — GitHub/GitLab PAT (Contents:Write + PullRequests:Write)
# VUL_FIX_API_KEY   — API key clients must send in X-API-Key header

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8007/api/v1/health/live')"

# workers=1 is REQUIRED — asyncio.Semaphore lives in one process.
# Scale horizontally via Kubernetes replicas, not uvicorn workers.
CMD ["python", "-m", "uvicorn", "api_server:app", \
     "--host", "0.0.0.0", \
     "--port", "8007", \
     "--workers", "1", \
     "--log-level", "info"]
