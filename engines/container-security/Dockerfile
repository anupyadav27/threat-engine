FROM python:3.9-slim

WORKDIR /app

COPY engines/container-security/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY engines/container-security/container_security_engine/ ./container_security_engine/
COPY engines/container-security/run_scan.py ./run_scan.py

COPY shared/common/ ./engine_common/
COPY shared/database/ ./consolidated_services/

ENV PYTHONPATH=/app
ENV PORT=8008

EXPOSE 8008

CMD ["python", "-m", "uvicorn", "container_security_engine.api_server:app", "--host", "0.0.0.0", "--port", "8008"]
