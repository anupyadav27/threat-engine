# =============================================================================
# Chat Engine — AI Query Platform
# Port: 8036
# =============================================================================

FROM python:3.11-slim AS builder

WORKDIR /app
COPY engines/chat/requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# -----------------------------------------------------------------------------
FROM python:3.11-slim

WORKDIR /app
COPY --from=builder /install /usr/local

# Shared utilities
COPY shared/common/ shared/common/
COPY shared/common/ engine_common/
COPY shared/auth/   engine_auth/

# Engine code
COPY engines/chat/ engines/chat/

# Make api_server importable from /app
RUN ln -s /app/engines/chat/api_server.py /app/api_server.py
RUN ln -s /app/engines/chat/chat_engine   /app/chat_engine

RUN useradd -r -s /bin/false appuser
USER appuser

EXPOSE 8036

ENTRYPOINT ["python", "-m", "engines.chat.api_server"]
