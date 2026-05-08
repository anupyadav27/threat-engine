FROM python:3.11-slim AS base

WORKDIR /app

# ── System dependencies ────────────────────────────────────────────────────────
# libpq-dev + gcc + build-essential — compile psycopg2 from source (production-safe)
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq-dev \
        gcc \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

# ── Python dependencies ────────────────────────────────────────────────────────
COPY engines/fix/threat_narrative/requirements.txt .

# Compile psycopg2 from source — binary wheel bundles private libpq, not recommended
# for production. Remove psycopg2-binary from requirements and install compiled version.
RUN pip install --no-cache-dir \
        psycopg2==2.9.9 \
    && grep -v "psycopg2" requirements.txt > /tmp/req_no_psycopg2.txt \
    && pip install --no-cache-dir -r /tmp/req_no_psycopg2.txt \
    && rm /tmp/req_no_psycopg2.txt

# ── Application source ─────────────────────────────────────────────────────────
COPY engines/fix/threat_narrative/threat_narrative_engine/ ./threat_narrative_engine/

# Auth module (destination matches Python imports: engine_auth.*)
COPY shared/auth/ ./engine_auth/

# ── Non-root user — reduce attack surface ─────────────────────────────────────
# Purge build tools after psycopg2 compilation to shrink the image attack surface
RUN apt-get purge -y --auto-remove gcc build-essential \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 1001 -s /bin/bash threatnarrative \
    && chown -R threatnarrative:threatnarrative /app

USER threatnarrative

EXPOSE 8040

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

# ── Required secrets (injected via Kubernetes secrets) ────────────────────────
# ANTHROPIC_API_KEY        — Anthropic Claude API key (optional — service degrades gracefully)
# MISTRAL_API_KEY          — Mistral AI fallback key (optional)
# THREAT_DB_HOST / THREAT_DB_PORT / THREAT_DB_NAME / THREAT_DB_USER / THREAT_DB_PASSWORD
# RISK_DB_*                — risk_scenarios table
# DATASEC_DB_*             — datasec_findings table
# CHECK_DB_*               — check_findings + rule_control_mapping tables
# DISCOVERIES_DB_*         — discovery_findings resource metadata
# CIEM_DB_*                — ciem_findings table

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8040/api/v1/health/live')"

# workers=1 is REQUIRED — asyncio event loop lives in one process.
# Scale horizontally via Kubernetes replicas, not uvicorn workers.
CMD ["uvicorn", "threat_narrative_engine.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8040", \
     "--workers", "1", \
     "--log-level", "info"]
