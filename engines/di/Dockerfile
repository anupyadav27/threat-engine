FROM python:3.11-slim

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y gcc && rm -rf /var/lib/apt/lists/*

# CSP scanner requirements (all providers: AWS/Azure/GCP/OCI/IBM/AliCloud/K8s)
COPY engines/di/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# ── CSP scanner classes (moved from engine-discoveries 2026-05-28) ────────────
COPY engines/di/providers/ ./providers/
COPY engines/di/common/ ./common/
COPY engines/di/utils/ ./utils/

# ── engine-di source ──────────────────────────────────────────────────────────
COPY engines/di/di_engine/ ./di_engine/
COPY engines/di/run_scan.py ./run_scan.py

# ── Shared utilities ──────────────────────────────────────────────────────────
# engine_common.*  (db_connections, orchestration, logger, etc.)
COPY shared/common/ ./engine_common/

# engine_auth.*  (require_permission, AuthMiddleware, dependencies)
COPY shared/auth/ ./engine_auth/

# engine_onboarding.*  — only SecretsManagerStorage (no EncryptionService/config chain)
RUN mkdir -p /app/engine_onboarding/storage
COPY engines/onboarding/__init__.py ./engine_onboarding/__init__.py
COPY engines/onboarding/storage/secrets_manager_storage.py ./engine_onboarding/storage/secrets_manager_storage.py
# Minimal __init__ that doesn't import EncryptionService (avoids pydantic_settings dep)
RUN printf '"""Minimal engine_onboarding.storage for DI engine."""\nfrom engine_onboarding.storage.secrets_manager_storage import secrets_manager_storage, SecretsManagerStorage\n__all__ = ["secrets_manager_storage", "SecretsManagerStorage"]\n' \
    > /app/engine_onboarding/storage/__init__.py

# Fix permissions — many source files are 600 (owner-only) on macOS and need to be world-readable
RUN find /app -type f -name "*.py" -exec chmod 644 {} + && \
    find /app -type d -exec chmod 755 {} +

ENV PYTHONPATH=/app
ENV PORT=8025

EXPOSE ${PORT}

# API server (long-running pod)
CMD ["sh", "-c", "uvicorn di_engine.api.api_server:app --host 0.0.0.0 --port ${PORT:-8025} --timeout-keep-alive 75"]
