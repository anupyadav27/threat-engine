FROM python:3.9-slim

WORKDIR /app

# Install dependencies
COPY engines/dbsec/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY engines/dbsec/dbsec_engine/ ./dbsec_engine/
COPY engines/dbsec/run_scan.py ./run_scan.py

# Copy shared common utilities
COPY shared/common/ ./engine_common/
COPY shared/database/ ./consolidated_services/

ENV PYTHONPATH=/app
ENV PORT=8007

EXPOSE 8007

CMD ["python", "-m", "uvicorn", "dbsec_engine.api_server:app", "--host", "0.0.0.0", "--port", "8007"]
