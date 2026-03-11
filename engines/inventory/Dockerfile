FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY engines/inventory/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code (destination paths match Python imports)
COPY engines/inventory/inventory_engine/ ./inventory_engine/
COPY shared/common/ ./engine_common/
COPY shared/database/ ./consolidated_services/
ENV PYTHONPATH=/app

# Expose port
EXPOSE 8022

# Run API server
CMD ["python", "-m", "uvicorn", "inventory_engine.api.api_server:app", "--host", "0.0.0.0", "--port", "8022"]
