FROM python:3.11-slim

WORKDIR /app

COPY engines/ciem/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY engines/ciem/ciem_engine/ ./ciem_engine/
COPY engines/ciem/run_scan.py ./run_scan.py
COPY engines/ciem/rules/ ./rules/
COPY shared/common/ ./engine_common/
COPY shared/database/ ./consolidated_services/
ENV PYTHONPATH=/app

EXPOSE 8025

CMD ["python", "-m", "uvicorn", "ciem_engine.api_server:app", "--host", "0.0.0.0", "--port", "8025"]
