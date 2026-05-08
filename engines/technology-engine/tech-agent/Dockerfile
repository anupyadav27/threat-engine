# Tech Scan Agent — lightweight Alpine image
# Build from repo root:
#   docker build -t yadavanup84/tech-scan-agent:v1 \
#     -f engines/technology-engine/tech-agent/Dockerfile \
#     engines/technology-engine/tech-agent
FROM python:3.12-alpine

LABEL org.opencontainers.image.title="tech-scan-agent" \
      org.opencontainers.image.description="Host-based CIS technology compliance scanner" \
      org.opencontainers.image.version="1.0.0"

# Install build deps for psycopg2-binary / pymysql
RUN apk add --no-cache \
    gcc \
    musl-dev \
    libffi-dev \
    && rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -S agent && adduser -S agent -G agent

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY agent.py .
COPY catalog_client.py .
COPY findings_client.py .
COPY local_executor.py .
COPY rule_evaluator.py .

# Drop root
USER agent

ENTRYPOINT ["python", "agent.py"]
