FROM python:3.9-slim

WORKDIR /app

COPY engines/cnapp/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY engines/cnapp/cnapp_engine/ ./cnapp_engine/

COPY shared/common/ ./engine_common/

ENV PYTHONPATH=/app
ENV CNAPP_PORT=8015

EXPOSE 8015

CMD ["python", "-m", "uvicorn", "cnapp_engine.api_server:app", "--host", "0.0.0.0", "--port", "8015"]
