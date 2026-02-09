FROM python:3.9-slim

WORKDIR /app

COPY engine_iam/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY engine_iam/iam_engine/ ./iam_engine/
COPY engine_common/ ./engine_common/

ENV PYTHONPATH=/app
ENV PORT=8003

EXPOSE 8003

CMD ["python", "-m", "uvicorn", "iam_engine.api_server:app", "--host", "0.0.0.0", "--port", "8003"]
