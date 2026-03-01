FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY shared/pipeline_worker/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy shared modules the worker imports
COPY shared/common/ ./shared/common/
COPY shared/pipeline_worker/ ./shared/pipeline_worker/

ENV PYTHONUNBUFFERED=1

CMD ["python", "-m", "shared.pipeline_worker.worker"]
