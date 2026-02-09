FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
# Note: Build context is root, so we need to copy from engine_onboarding/
COPY engine_onboarding/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy onboarding module
COPY engine_onboarding/ ./engine_onboarding/
COPY engine_common/ ./engine_common/

# Set Python path
ENV PYTHONPATH=/app

# Allow PORT to be configured via environment variable
ENV PORT=8000

# Expose port
EXPOSE ${PORT}

# Run API server with configurable port
CMD ["sh", "-c", "python -m uvicorn engine_onboarding.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
