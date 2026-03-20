FROM python:3.9-slim

WORKDIR /app

COPY engines/iam/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code (destination paths match Python imports)
COPY engines/iam/iam_engine/ ./iam_engine/

# Run scan entry point (for K8s Job execution)
COPY engines/iam/run_scan.py ./run_scan.py

COPY shared/common/ ./engine_common/

ENV PYTHONPATH=/app
ENV PORT=8003

EXPOSE 8003

CMD ["python", "-m", "uvicorn", "iam_engine.api_server:app", "--host", "0.0.0.0", "--port", "8003"]
