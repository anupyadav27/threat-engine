FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY engine_inventory/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY engine_inventory/inventory_engine/ ./inventory_engine/
COPY engine_common/ ./engine_common/
ENV PYTHONPATH=/app

# Expose port
EXPOSE 8022

# Run API server
CMD ["python", "-m", "uvicorn", "inventory_engine.api.api_server:app", "--host", "0.0.0.0", "--port", "8022"]

