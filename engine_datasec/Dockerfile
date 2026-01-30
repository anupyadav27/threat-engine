FROM python:3.9-slim

WORKDIR /app

# Install dependencies
COPY engine_datasec/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY engine_datasec/data_security_engine/ ./data_security_engine/
COPY engine_datasec/config/ ./config/
COPY engine_datasec/scripts/ ./scripts/
COPY engine_common/ ./engine_common/
COPY consolidated_services/ ./consolidated_services/

# Set environment variables
ENV PYTHONPATH=/app
ENV PORT=8000

# Expose port
EXPOSE 8000

# Run API server
CMD ["python", "-m", "uvicorn", "data_security_engine.api_server:app", "--host", "0.0.0.0", "--port", "8000"]

