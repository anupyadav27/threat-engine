FROM python:3.11-slim AS base

WORKDIR /app

COPY engines/pipeline-monitor/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Shared libraries
COPY shared/common/ /app/engine_common/
COPY shared/database/ /app/database/

# Engine code
COPY engines/pipeline-monitor/ /app/

RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8012

CMD ["python", "-m", "uvicorn", "pipeline_monitor_engine.api_server:app", \
     "--host", "0.0.0.0", "--port", "8012"]
