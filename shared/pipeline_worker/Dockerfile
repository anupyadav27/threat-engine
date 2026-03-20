FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY shared/pipeline_worker/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy shared modules the worker imports
COPY shared/common/ ./shared/common/
COPY shared/pipeline_worker/ ./shared/pipeline_worker/

ENV PYTHONUNBUFFERED=1

EXPOSE 8050

CMD ["uvicorn", "shared.pipeline_worker.worker:app", "--host", "0.0.0.0", "--port", "8050"]
