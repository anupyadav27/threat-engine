FROM python:3.11-slim

WORKDIR /app

# System deps for psycopg2 and git
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY engine/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy engine source
COPY engine/ .

# Copy rule metadata (secrets_docs) so the container has rules available
COPY secrets_docs/ /app/secrets_docs/

# Non-root user for production security
RUN useradd -m -u 1001 secopsfix && chown -R secopsfix /app
USER secopsfix

EXPOSE 8006

ENV SECOPS_FIX_PORT=8006 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8006/api/v1/health/live')"

CMD ["uvicorn", "api_server:app", "--host", "0.0.0.0", "--port", "8006"]
