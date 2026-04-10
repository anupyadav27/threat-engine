FROM python:3.9-slim

WORKDIR /app

COPY engines/database-security/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY engines/database-security/database_security_engine/ ./database_security_engine/
COPY engines/database-security/run_scan.py ./run_scan.py

COPY shared/common/ ./engine_common/
COPY shared/database/ ./consolidated_services/

ENV PYTHONPATH=/app
ENV PORT=8007

EXPOSE 8007

CMD ["python", "-m", "uvicorn", "database_security_engine.api_server:app", "--host", "0.0.0.0", "--port", "8007"]
