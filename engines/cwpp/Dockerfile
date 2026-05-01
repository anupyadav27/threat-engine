FROM python:3.9-slim

WORKDIR /app

COPY engines/cwpp/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY engines/cwpp/cwpp_engine/ ./cwpp_engine/

COPY shared/common/ ./engine_common/

ENV PYTHONPATH=/app
ENV CWPP_PORT=8016

EXPOSE 8016

CMD ["python", "-m", "uvicorn", "cwpp_engine.api_server:app", "--host", "0.0.0.0", "--port", "8016"]
