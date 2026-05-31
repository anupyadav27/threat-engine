FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (layer caching)
COPY engines/attack-path/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code — paths match Python import expectations
COPY engines/attack-path/attack_path_engine/ ./attack_path_engine/
COPY shared/common/ ./engine_common/
COPY shared/auth/ ./engine_auth/

ENV PYTHONPATH=/app

EXPOSE 8025

CMD ["uvicorn", "attack_path_engine.main:app", "--host", "0.0.0.0", "--port", "8025"]
