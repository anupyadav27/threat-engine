FROM python:3.11-slim

WORKDIR /app

COPY engines/cdr/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY engines/cdr/cdr_engine/ ./cdr_engine/
COPY engines/cdr/run_scan.py ./run_scan.py
COPY engines/cdr/rules/ ./rules/
COPY shared/common/ ./engine_common/
COPY shared/auth/ ./engine_auth/
COPY shared/database/ ./consolidated_services/
ENV PYTHONPATH=/app

EXPOSE 8025

CMD ["python", "-m", "uvicorn", "cdr_engine.api_server:app", "--host", "0.0.0.0", "--port", "8025"]
